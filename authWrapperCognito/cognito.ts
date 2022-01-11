import {
    Auth,
    AuthSuccessPayload,
    AuthError,
    GetSessionResult,
    CookieConfig,
    AttributeSet,
} from './auth'
import * as AmazonCognitoIdentity from 'amazon-cognito-identity-js'
import { props } from 'ramda'
import { timeHasPassed, mergeProps } from '../lib/utils'
import axios, { AxiosInstance } from 'axios'

const COOKIE_OPTIONS = { path: '/', httpOnly: true }
const COOKIE_ID_TOKEN = 'id_token'
const COOKIE_ACCESS_TOKEN = 'access_token'
const COOKIE_REFRESH_TOKEN = 'refresh_token'

export type CognitoTokenSet = {
    idToken: AmazonCognitoIdentity.CognitoIdToken
    accessToken: AmazonCognitoIdentity.CognitoAccessToken
    refreshToken: AmazonCognitoIdentity.CognitoRefreshToken
}

export type CognitoUserPoolFactory = (
    data: AmazonCognitoIdentity.ICognitoUserPoolData,
    wrapRefreshSessionCallback?: (
        target: AmazonCognitoIdentity.NodeCallback.Any
    ) => AmazonCognitoIdentity.NodeCallback.Any
) => AmazonCognitoIdentity.CognitoUserPool

export type CognitoUserFactory = (
    data: AmazonCognitoIdentity.ICognitoUserData
) => AmazonCognitoIdentity.CognitoUser

export type CognitoUserAttributeFactory = (
    data: AmazonCognitoIdentity.ICognitoUserAttributeData
) => AmazonCognitoIdentity.CognitoUserAttribute

export type CognitoAuthenticationDetailsFactory = (
    data: AmazonCognitoIdentity.IAuthenticationDetailsData
) => AmazonCognitoIdentity.AuthenticationDetails

export type CognitoUserSessionFactory = (
    data: AmazonCognitoIdentity.ICognitoUserSessionData
) => AmazonCognitoIdentity.CognitoUserSession

export type CognitoAccessTokenFactory = ({
    AccessToken,
}: {
    AccessToken: string
}) => AmazonCognitoIdentity.CognitoAccessToken

export type CognitoIdTokenFactory = ({
    IdToken,
}: {
    IdToken: string
}) => AmazonCognitoIdentity.CognitoIdToken

export type CognitoRefreshTokenFactory = ({
    RefreshToken,
}: {
    RefreshToken: string
}) => AmazonCognitoIdentity.CognitoRefreshToken

export type CognitoData = {
    userPoolId: string
    clientId: string
    attributes: string[]
    cognitoUserPoolFactory: CognitoUserPoolFactory
    cognitoUserFactory: CognitoUserFactory
    cognitoUserAttributeFactory: CognitoUserAttributeFactory
    cognitoAuthenticationDetailsFactory: CognitoAuthenticationDetailsFactory
    cognitoUserSessionFactory: CognitoUserSessionFactory
    cognitoAccessTokenFactory: CognitoAccessTokenFactory
    cognitoIdTokenFactory: CognitoIdTokenFactory
    cognitoRefreshTokenFactory: CognitoRefreshTokenFactory
    axios: AxiosInstance
}

export class CognitoAuth implements Auth {
    private userPool: AmazonCognitoIdentity.CognitoUserPool
    private cognitoUserFactory: CognitoUserFactory
    private cognitoUserAttributeFactory: CognitoUserAttributeFactory
    private cognitoAuthenticationDetailsFactory: CognitoAuthenticationDetailsFactory
    private cognitoUserSessionFactory: CognitoUserSessionFactory
    private cognitoAccessTokenFactory: CognitoAccessTokenFactory
    private cognitoIdTokenFactory: CognitoIdTokenFactory
    private cognitoRefreshTokenFactory: CognitoRefreshTokenFactory
    private attributes: string[]
    private axios: AxiosInstance
    private awsRegion: string

    constructor({
        userPoolId,
        clientId,
        attributes,
        cognitoUserPoolFactory,
        cognitoUserFactory,
        cognitoUserAttributeFactory,
        cognitoAuthenticationDetailsFactory,
        cognitoUserSessionFactory,
        cognitoAccessTokenFactory,
        cognitoIdTokenFactory,
        cognitoRefreshTokenFactory,
        axios,
    }: CognitoData) {
        const poolData = {
            UserPoolId: userPoolId,
            ClientId: clientId,
        }

        this.userPool = cognitoUserPoolFactory(poolData)
        this.cognitoUserFactory = cognitoUserFactory
        this.cognitoUserAttributeFactory = cognitoUserAttributeFactory
        this.cognitoAuthenticationDetailsFactory =
            cognitoAuthenticationDetailsFactory
        this.cognitoUserSessionFactory = cognitoUserSessionFactory
        this.cognitoAccessTokenFactory = cognitoAccessTokenFactory
        this.cognitoIdTokenFactory = cognitoIdTokenFactory
        this.cognitoRefreshTokenFactory = cognitoRefreshTokenFactory
        this.axios = axios
        this.attributes = attributes
        this.awsRegion = this.extractAwsRegionFromUserPoolId()
    }

    async init() {}

    login(email: string, password: string): Promise<AuthSuccessPayload> {
        return new Promise((resolve, reject) => {
            var authenticationDetails =
                this.cognitoAuthenticationDetailsFactory({
                    Username: email,
                    Password: password,
                })

            var userData = {
                Username: email,
                Pool: this.userPool,
            }

            var cognitoUser = this.cognitoUserFactory(userData)

            const buildCookies = this.buildCookies

            const authAttributes = this.attributes

            cognitoUser.authenticateUser(authenticationDetails, {
                onSuccess: function (result) {
                    if (!result.isValid()) {
                        return reject(new Error(`Login failed`))
                    }

                    const tokenSet: CognitoTokenSet = {
                        idToken: result.getIdToken(),
                        accessToken: result.getAccessToken(),
                        refreshToken: result.getRefreshToken(),
                    }

                    const idTokenPayload = result.getIdToken().payload

                    const attributes = mergeProps(
                        {},
                        idTokenPayload,
                        authAttributes
                    )

                    return resolve({
                        cookies: buildCookies(tokenSet),
                        attributes,
                    })
                },
                onFailure: function (err) {
                    if (err.code === 'NotAuthorizedException') {
                        console.error(err)

                        return reject(
                            new Error(AuthError.IncorrectEmailOrPassword)
                        )
                    }

                    if (err.code === 'UserNotConfirmedException') {
                        console.error(err)

                        return reject(new Error(AuthError.UserNotConfirmed))
                    }

                    reject(err)
                },
            })
        })
    }

    async editUserAttributes(
        cookies: Record<string, string>,
        attributes: AttributeSet[]
    ): Promise<void> {
        const attributeValues = attributes.map(
            this.toRequestAttribute.bind(this)
        )

        const accessToken = cookies[COOKIE_ACCESS_TOKEN]

        if (!accessToken) {
            console.error(
                `Cognito: Access token not provided in the cookie object.`
            )

            throw new Error(AuthError.AuthCookieMissing)
        }

        const url = `https://cognito-idp.${this.awsRegion}.amazonaws.com/`

        await this.axios.post(
            url,
            {
                AccessToken: accessToken,
                UserAttributes: attributeValues,
            },
            {
                headers: {
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Target':
                        'AWSCognitoIdentityProviderService.UpdateUserAttributes',
                },
            }
        )
    }

    async getSession(
        cookies: Record<string, string>
    ): Promise<GetSessionResult> {
        const [accessToken, idToken, refreshToken] = props(
            [COOKIE_ID_TOKEN, COOKIE_ACCESS_TOKEN, COOKIE_REFRESH_TOKEN],
            cookies
        )

        if (!accessToken || !idToken || !refreshToken) {
            console.error(
                `Cognito: Token information is not complete in order to get the user session.`
            )

            throw new Error(AuthError.FailedToGetSession)
        }

        const session = this.cognitoUserSessionFactory({
            AccessToken: this.cognitoAccessTokenFactory({
                AccessToken: accessToken,
            }),
            IdToken: this.cognitoIdTokenFactory({ IdToken: idToken }),
            RefreshToken: this.cognitoRefreshTokenFactory({
                RefreshToken: refreshToken,
            }),
        })

        if (!session.isValid()) {
            throw new Error(AuthError.FailedToGetSession)
        }

        const shouldRefreshTokens = timeHasPassed(
            session.getAccessToken().getExpiration()
        )

        const tokenSet = shouldRefreshTokens
            ? await this.refreshToken(session)
            : null

        return {
            session: {
                userEmail: session.getAccessToken().payload.email,
            },
            cookies: tokenSet ? this.buildCookies(tokenSet) : [],
            generatedNewTokens: shouldRefreshTokens,
        }
    }

    async signup(
        email: string,
        password: string,
        clientMetadata?: Record<string, any>
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            var attributeList = []

            attributeList.push(
                this.cognitoUserAttributeFactory({
                    Name: 'email',
                    Value: email,
                })
            )

            attributeList = attributeList.concat(
                this.attributes.map((attributeName: string) =>
                    this.cognitoUserAttributeFactory({
                        Name: attributeName,
                        Value: '',
                    })
                )
            )

            this.userPool.signUp(
                email,
                password,
                attributeList,
                [],
                function (err, result) {
                    if (err) {
                        return reject(err)
                    }

                    if (!result) {
                        return reject(new Error('Failed to signup.'))
                    }

                    const cognitoUser = result.user

                    return resolve()
                },
                clientMetadata
            )
        })
    }

    requestPasswordReset(
        email: string,
        clientMetadata: Record<string, any>
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            const userData = {
                Username: email,
                Pool: this.userPool,
            }

            var user = this.cognitoUserFactory(userData)

            if (!user) {
                console.error(
                    `requestPasswordReset: Could not retrieve user: ${email}`
                )

                new Error(AuthError.FailedToRequestPasswordReset)
            }

            user.forgotPassword(
                {
                    onSuccess: resolve,
                    onFailure: reject,
                },
                clientMetadata
            )
        })
    }

    resetPassword(
        email: string,
        password: string,
        code: string
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            const userData = {
                Username: email,
                Pool: this.userPool,
            }

            var user = this.cognitoUserFactory(userData)

            if (!user) {
                console.error(
                    `resetPassword: Could not retrieve user: ${email}`
                )

                new Error(AuthError.FailedToResetPassword)
            }

            user.confirmPassword(code, password, {
                onSuccess: resolve,
                onFailure: (err: any) => {
                    if (this.isInvalidResetPasswordError(err.code)) {
                        console.error(err)

                        return reject(
                            new Error(AuthError.FailedToResetPassword)
                        )
                    }

                    reject(err)
                },
            })
        })
    }

    confirmSignup(email: string, code: string): Promise<void> {
        return new Promise((resolve, reject) => {
            console.info(`Cognito: Starting confirm user operation.`)

            const userData = {
                Username: email,
                Pool: this.userPool,
            }

            var user = this.cognitoUserFactory(userData)

            if (!user) {
                console.error(
                    `confirmSignup: Could not confirm signup for user: ${email}`
                )

                new Error(AuthError.FailedToConfirmSignup)
            }

            user.confirmRegistration(code, false, (err) => {
                if (err) {
                    console.info(
                        `Cognito: Failed to confirm registration for user ${email}`
                    )

                    console.error(err)

                    return reject(new Error(AuthError.FailedToConfirmSignup))
                }

                console.info(
                    `Cognito: User confirmation finished successfully.`
                )

                return resolve()
            })
        })
    }

    private toRequestAttribute([attributeName, attributeValue]: AttributeSet) {
        return {
            Name: attributeName,
            Value: attributeValue,
        }
    }

    private buildCookies({
        idToken,
        accessToken,
        refreshToken,
    }: CognitoTokenSet): CookieConfig[] {
        return [
            {
                name: COOKIE_ID_TOKEN,
                value: idToken.getJwtToken(),
                options: COOKIE_OPTIONS,
            },
            {
                name: COOKIE_ACCESS_TOKEN,
                value: accessToken.getJwtToken(),
                options: COOKIE_OPTIONS,
            },
            {
                name: COOKIE_REFRESH_TOKEN,
                value: refreshToken.getToken(),
                options: COOKIE_OPTIONS,
            },
        ]
    }

    private isInvalidResetPasswordError(error: string) {
        return (
            [
                'ExpiredCodeException',
                'LimitExceededException',
                'CodeMismatchException',
                'InvalidPasswordException',
            ].indexOf(error) > -1
        )
    }

    private refreshToken(
        session: AmazonCognitoIdentity.CognitoUserSession
    ): Promise<CognitoTokenSet> {
        return new Promise((resolve, reject) => {
            const email = session.getAccessToken().payload.email

            console.info(`Cognito: Refreshing token for ${email}`)

            const userData = {
                Username: email,
                Pool: this.userPool,
            }

            this.cognitoUserFactory(userData).refreshSession(
                session.getRefreshToken(),
                (error: any, result: any) => {
                    if (error) {
                        console.error(`Cognito: Failed to refresh session.`)

                        return reject(error)
                    }

                    resolve({
                        idToken: result.idToken,
                        accessToken: result.accessToken,
                        refreshToken: result.refreshToken,
                    })
                }
            )
        })
    }

    private extractAwsRegionFromUserPoolId(): string {
        const splitResult = (process.env.AUTH_COGNITO_USER_POOL_ID || '').split(
            '_'
        )

        if (splitResult.length === 0) {
            throw new Error(`Failed to extract AWS Region from Pool ID.`)
        }

        return splitResult[0]
    }
}

export default CognitoAuth

const cognitoUserPoolFactory = (
    data: AmazonCognitoIdentity.ICognitoUserPoolData,
    wrapRefreshSessionCallback?: (
        target: AmazonCognitoIdentity.NodeCallback.Any
    ) => AmazonCognitoIdentity.NodeCallback.Any
) => new AmazonCognitoIdentity.CognitoUserPool(data, wrapRefreshSessionCallback)

const cognitoUserFactory = (data: AmazonCognitoIdentity.ICognitoUserData) =>
    new AmazonCognitoIdentity.CognitoUser(data)

const cognitoUserAttributeFactory = (
    data: AmazonCognitoIdentity.ICognitoUserAttributeData
) => new AmazonCognitoIdentity.CognitoUserAttribute(data)

const cognitoAuthenticationDetailsFactory = (
    data: AmazonCognitoIdentity.IAuthenticationDetailsData
) => new AmazonCognitoIdentity.AuthenticationDetails(data)

const cognitoUserSessionFactory = (
    data: AmazonCognitoIdentity.ICognitoUserSessionData
) => new AmazonCognitoIdentity.CognitoUserSession(data)

const cognitoAccessTokenFactory = ({ AccessToken }: { AccessToken: string }) =>
    new AmazonCognitoIdentity.CognitoAccessToken({ AccessToken })

const cognitoIdTokenFactory = ({ IdToken }: { IdToken: string }) =>
    new AmazonCognitoIdentity.CognitoIdToken({ IdToken })

const cognitoRefreshTokenFactory = ({
    RefreshToken,
}: {
    RefreshToken: string
}) => new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken })

export const getCognitoAuth = (
    userPoolId: string,
    clientId: string,
    attributes: string[]
): CognitoAuth => {
    return new CognitoAuth({
        userPoolId,
        clientId,
        attributes,
        cognitoUserPoolFactory,
        cognitoUserFactory,
        cognitoUserAttributeFactory,
        cognitoAuthenticationDetailsFactory,
        cognitoUserSessionFactory,
        cognitoAccessTokenFactory,
        cognitoIdTokenFactory,
        cognitoRefreshTokenFactory,
        axios,
    })
}
