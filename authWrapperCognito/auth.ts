import {
    GetServerSidePropsContext,
    NextApiRequest,
    NextApiResponse,
} from 'next'
import { serialize, CookieSerializeOptions } from 'cookie'
import { getCognitoAuth } from './cognito'
import { UserRepository, RepositoryError } from '../repository/repository'
import { User, JwtUtil } from '../types'
import * as userlib from '../lib/user'
import { isEmptyString } from '../lib/utils'

const AUTH_JWT_SECRET = process.env.AUTH_JWT_SECRET || ''

export const AUTH_ATTR_FIRST_NAME = 'given_name'
export const AUTH_ATTR_LAST_NAME = 'family_name'

export type AttributeSet = [string, string]

export const COOKIE_AUTH = 'auth'

export const AuthError = {
    IncorrectEmailOrPassword: 'IncorrectEmailOrPassword',
    EmailRegisteredAlready: 'EmailRegisteredAlready',
    UserNotConfirmed: 'UserNotConfirmed',
    FailedToRequestPasswordReset: 'FailedToRequestPasswordReset',
    FailedToResetPassword: 'FailedToResetPassword',
    FailedToConfirmSignup: 'FailedToConfirmSignup',
    FailedToGetSession: 'FailedToGetSession',
    FailedToEditUserAttributes: 'FailedToEditUserAttributes',
    AuthCookieMissing: 'AuthCookieMissing',
}

const CognitoError = {
    InvalidPasswordException: 'InvalidPasswordException',
    UsernameExistsException: 'UsernameExistsException',
    InvalidParameterException: 'InvalidParameterException',
}

export type CookieConfig = {
    name: string
    value: string
    options?: CookieSerializeOptions
}

export type AuthAttributes = Record<string, string>

export type AuthSuccessPayload = {
    cookies: CookieConfig[]
    attributes: AuthAttributes
}

type ClientMetadata = {
    message: string
    codeTemplate?: string //placeholder for '{{CODE}}'
    subject?: string //
    emailTemplate?: string //placeholder for email {{EMAIL}}
}

export type AuthLoginFunc = (
    email: string,
    password: string
) => Promise<AuthSuccessPayload>

export type AuthSignupFunc = (
    email: string,
    password: string,
    clientMetadata: ClientMetadata
) => Promise<void>

export type AuthResetPasswordFunc = (
    email: string,
    password: string,
    code: string
) => Promise<void>

export type AuthConfirmSignupFunc = (
    email: string,
    code: string
) => Promise<void>

export type GetSessionResult = {
    session: Session
    cookies: CookieConfig[]
    generatedNewTokens: boolean
}

export type GetSessionFunc = (
    cookies: Record<string, string>
) => Promise<GetSessionResult>

export type EditUserAttributesFunc = (
    cookies: Record<string, string>,
    attributes: AttributeSet[]
) => Promise<void>

export type Session = {
    userEmail: string
}

export type AuthRequestPasswordResetFunc = (
    email: string,
    clientMetadata: ClientMetadata
) => Promise<void>

export type Auth = {
    init: () => Promise<void>
    login: AuthLoginFunc
    signup: AuthSignupFunc
    requestPasswordReset: AuthRequestPasswordResetFunc
    resetPassword: AuthResetPasswordFunc
    confirmSignup: AuthConfirmSignupFunc
    getSession: GetSessionFunc
    editUserAttributes: EditUserAttributesFunc
}

export type AuthenticationResult = {
    isAuthenticated: boolean
    userEmail: string
    userId: number
    certified: boolean
    attempted: boolean
}

export type AuthTokenPayload = {
    userId: number
    userEmail: string
    certified: boolean
    attempted: boolean
}

export type DecodedAuthToken = AuthTokenPayload & {
    success: boolean
}

export type SessionProps = {
    authenticated: boolean
    userEmail: string
}

export const AUTHENTICATION_RESULT_EMPTY = {
    isAuthenticated: false,
    userEmail: '',
    userId: 0,
    certified: false,
    attempted: false,
}

const parseDecodedAuthToken = (
    payload: Record<string, any>,
    err: Error | null
): DecodedAuthToken => {
    if (err) {
        console.error(err)

        return {
            success: false,
            ...AUTHENTICATION_RESULT_EMPTY,
        }
    }

    if (!payload.userId) {
        console.error('Token is malformed.')

        return {
            success: false,
            ...AUTHENTICATION_RESULT_EMPTY,
            certified: false,
            attempted: false,
        }
    }

    return {
        success: true,
        userId: payload.userId,
        userEmail: payload.userEmail,
        certified: payload.certified,
        attempted: payload.attempted,
    }
}

export const authenticateFromContext = async (
    jwt: JwtUtil,
    context: GetServerSidePropsContext,
    auth: Auth
): Promise<AuthenticationResult> => {
    try {
        if (!authTokenIsIncludedInRequest(context.req.cookies || {})) {
            return AUTHENTICATION_RESULT_EMPTY
        }

        const {
            session,
            cookies: newCookies,
            generatedNewTokens,
        } = await auth.getSession(context.req.cookies || {})

        if (generatedNewTokens) {
            context.res.setHeader(
                'Set-Cookie',
                newCookies.map((cookie: CookieConfig) =>
                    serialize(cookie.name, cookie.value, cookie.options)
                )
            )
        }

        return await authenticateFromAuthToken(
            jwt,
            context.req.cookies[COOKIE_AUTH],
            session as any
        )
    } catch (err) {
        console.error(err)

        return AUTHENTICATION_RESULT_EMPTY
    }
}

export const authenticateFromRequest = async (
    jwt: JwtUtil,
    request: NextApiRequest,
    response: NextApiResponse,
    auth: Auth
): Promise<AuthenticationResult> => {
    const cookies = request.cookies

    if (!authTokenIsIncludedInRequest(cookies || {})) {
        return AUTHENTICATION_RESULT_EMPTY
    }

    if (!cookies || !cookies[COOKIE_AUTH]) return AUTHENTICATION_RESULT_EMPTY

    const {
        session,
        cookies: newCookies,
        generatedNewTokens,
    } = await auth.getSession(request.cookies || {})

    if (generatedNewTokens) {
        response.setHeader(
            'Set-Cookie',
            newCookies.map((cookie: CookieConfig) =>
                serialize(cookie.name, cookie.value, cookie.options)
            )
        )
    }

    return await authenticateFromAuthToken(jwt, cookies[COOKIE_AUTH], session)
}

const authenticateFromAuthToken = async (
    jwt: JwtUtil,
    authToken: string,
    session: Session
) => {
    const { success, userId, userEmail, certified, attempted } =
        await jwt.decodeToken<DecodedAuthToken>(
            AUTH_JWT_SECRET,
            authToken,
            parseDecodedAuthToken
        )

    if (!success) {
        return AUTHENTICATION_RESULT_EMPTY
    }

    if (userEmail !== session.userEmail) {
        console.error(
            `Emails between tokens don't match: "${session.userEmail}" and "${userEmail}"`
        )

        throw new Error(AuthError.FailedToGetSession)
    }

    return {
        isAuthenticated: true,
        userEmail: session.userEmail,
        userId,
        certified,
        attempted,
    }
}

export const getAuthComponent = (): Auth => {
    return getCognitoAuth(
        process.env.AUTH_COGNITO_USER_POOL_ID || '',
        process.env.AUTH_COGNITO_CLIENT_ID || '',
        [AUTH_ATTR_FIRST_NAME, AUTH_ATTR_LAST_NAME]
    )
}

export const updateSession = async (
    jwt: JwtUtil,
    res: NextApiResponse,
    user: User,
    cookies: CookieConfig[]
) => {
    const appTokenPayload: AuthTokenPayload = {
        userId: user.id,
        userEmail: user.email,
        certified: user.certified,
        attempted: user.attempted,
    }

    const appToken = await jwt.sign(AUTH_JWT_SECRET, appTokenPayload)

    res.setHeader(
        'Set-Cookie',
        cookies
            .map((cookie: CookieConfig) =>
                serialize(cookie.name, cookie.value, cookie.options)
            )
            .concat(
                serialize(COOKIE_AUTH, appToken, { path: '/', httpOnly: true })
            )
    )
}

export const authenticate = async (
    auth: Auth,
    jwt: JwtUtil,
    userRepository: UserRepository,
    res: NextApiResponse,
    email: string,
    password: string
): Promise<AuthSuccessPayload> => {
    await auth.init()

    const loginResult = await auth.login(email, password)

    const [user, userExists] = await getUserByEmail(userRepository, email)

    const firstName = loginResult.attributes[AUTH_ATTR_FIRST_NAME] || ''
    const lastName = loginResult.attributes[AUTH_ATTR_LAST_NAME] || ''

    if (!userExists) {
        console.info(
            `Auth: Attempted to login with an existing user in the authentication layer but does not exist in the database. A new user entity will be created for that user now: ${email}`
        )
    }

    const userModified = userExists
        ? await syncUser(userRepository, user, firstName, lastName)
        : await createNewUser(userRepository, email, firstName, lastName)

    await updateSession(jwt, res, userModified, loginResult.cookies)

    return loginResult
}

export const requestPasswordReset = async (
    email: string,
    clientMetadata: ClientMetadata
): Promise<void> => {
    const auth = getAuthComponent()

    await auth.init()

    await auth.requestPasswordReset(email, clientMetadata)
}

export const resetPassword = async (
    email: string,
    password: string,
    code: string
): Promise<void> => {
    const auth = getAuthComponent()

    await auth.init()

    await auth.resetPassword(email, password, code)
}

export const confirmSignup = async (
    email: string,
    code: string
): Promise<void> => {
    const auth = getAuthComponent()

    await auth.init()

    await auth.confirmSignup(email, code)
}

export const signup = async (
    auth: Auth,
    email: string,
    password: string,
    clientMetadata: ClientMetadata
): Promise<void> => {
    try {
        await auth.init()

        await auth.signup(email, password, clientMetadata)
    } catch (err: any) {
        if (
            err.name === CognitoError.InvalidPasswordException ||
            err.name === CognitoError.InvalidParameterException
        ) {
            console.error(err)

            throw new Error(AuthError.IncorrectEmailOrPassword)
        }

        if (err.name === CognitoError.UsernameExistsException) {
            console.error(err)

            throw new Error(AuthError.EmailRegisteredAlready)
        }

        throw err
    }
}

export const editUserAttributes = async (
    auth: Auth,
    cookies: Record<string, string>,
    attributes: AttributeSet[]
): Promise<void> => {
    await auth.editUserAttributes(cookies, attributes)
}

export const isAuthenticationError = (error: string): boolean =>
    Object.keys(AuthError).indexOf(error) > -1

const authTokenIsIncludedInRequest = (cookies: Record<string, string>) =>
    cookies.hasOwnProperty(COOKIE_AUTH) && cookies[COOKIE_AUTH].trim() !== ''

const getUserByEmail = async (
    repository: UserRepository,
    email: string
): Promise<[User, boolean]> => {
    try {
        return [await repository.getByEmail(email), true]
    } catch (err) {
        if (err.message === RepositoryError.UserNotFound) {
            return [userlib.emptyUserWithEmail(email), false]
        }

        throw err
    }
}

const createNewUser = async (
    repository: UserRepository,
    email: string,
    firstName: string,
    lastName: string
): Promise<User> =>
    await repository.add({
        id: 0,
        firstName,
        lastName,
        email,
        attempted: false,
        certified: false,
        vclink: '',
        answerStore: [],
        skillname: '',
    })

const syncUser = async (
    repository: UserRepository,
    user: User,
    firstName: string,
    lastName: string
): Promise<User> => {
    const userNameMatch =
        firstName === user.firstName && lastName === user.lastName

    if (isEmptyString(firstName) || isEmptyString(lastName) || userNameMatch) {
        return user
    }

    const userModified = {
        ...user,
        firstName,
        lastName,
    }

    await repository.edit({
        ...user,
    })

    return userModified
}
