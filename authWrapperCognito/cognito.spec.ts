import { CognitoAuth } from './cognito'
import { Auth } from './auth'

const USER_POOL_ID = 'USER_POOL_ID'
const CLIENT_ID = 'CLIENT_ID'

var cognitoUserPoolFactory: any
var cognitoUserMock: any
var cognitoUserSessionMock: any
var cognitoUserPoolMock: any
var cognitoUserFactory: any
const cognitoUserAttributeFactory = (): any => ({})
var cognitoAuthenticationDetailsFactory: any
var cognitoUserSessionFactory: any
var cognitoAccessTokenFactory: any
var cognitoIdTokenFactory: any
var cognitoRefreshTokenFactory: any
var axiosMock: any

const EMAIL = 'some_email@example.com'
const PASSWORD = 'some_password'

var cognito: Auth | null = null

beforeEach(() => {
    cognitoUserPoolMock = {
        signUp: jest.fn((_email, _password, _attributeList, _, callback) => {
            callback(null, { user: 'some_user' })
        }),
    }

    cognitoUserPoolFactory = (): any => cognitoUserPoolMock

    cognitoUserMock = {
        authenticateUser: jest.fn((_data, { onSuccess }) => {
            onSuccess({
                isValid: jest.fn(() => true),
                getIdToken: jest.fn(() => ({
                    getJwtToken: jest.fn(() => 'id_jwt_token'),
                })),
                getAccessToken: jest.fn(() => ({
                    getJwtToken: jest.fn(() => 'access_jwt_token'),
                })),
                getRefreshToken: jest.fn(() => ({
                    getToken: jest.fn(() => 'refresh_token'),
                })),
            })
        }),
        forgotPassword: jest.fn(),
        confirmPassword: jest.fn(),
        confirmRegistration: jest.fn(),
        user: {},
    }

    cognitoUserSessionMock = {}

    cognitoUserFactory = (_userData: any): any => cognitoUserMock

    cognitoAuthenticationDetailsFactory = jest.fn((data) => ({
        ...data,
        COGNITO_AUTHENTICATION_DETAILS: 'COGNITO_AUTHENTICATION_DETAILS',
    }))

    cognitoUserSessionFactory = (_userSession: any): any =>
        cognitoUserSessionMock

    cognitoAccessTokenFactory = (_data: any): any => ({})

    cognitoIdTokenFactory = (_data: any): any => ({})

    cognitoRefreshTokenFactory = (_data: any): any => ({})

    axiosMock = {}

    cognito = new CognitoAuth({
        userPoolId: USER_POOL_ID,
        clientId: CLIENT_ID,
        attributes: [],
        cognitoUserPoolFactory,
        cognitoUserFactory,
        cognitoUserAttributeFactory,
        cognitoAuthenticationDetailsFactory:
            cognitoAuthenticationDetailsFactory as any,
        cognitoUserSessionFactory,
        cognitoAccessTokenFactory,
        cognitoIdTokenFactory,
        cognitoRefreshTokenFactory,
        axios: axiosMock,
    })
})

test('login()', async () => {
    await (cognito as Auth).login(EMAIL, PASSWORD)

    expect(cognitoAuthenticationDetailsFactory).toHaveBeenCalledTimes(1)

    expect(cognitoAuthenticationDetailsFactory).toHaveBeenCalledWith({
        Username: EMAIL,
        Password: PASSWORD,
    })

    expect(cognitoUserMock.authenticateUser).toHaveBeenCalledTimes(1)

    expect(cognitoUserMock.authenticateUser).toHaveBeenCalledWith(
        {
            COGNITO_AUTHENTICATION_DETAILS: 'COGNITO_AUTHENTICATION_DETAILS',
            Username: EMAIL,
            Password: PASSWORD,
        },
        expect.any(Object)
    )
})

test('signup()', async () => {
    const customMessage = {
        message: 'some_message',
    }
    await (cognito as Auth).signup(EMAIL, PASSWORD, customMessage)

    expect(cognitoUserPoolMock.signUp).toHaveBeenCalledTimes(1)

    expect(cognitoUserPoolMock.signUp).toHaveBeenCalledWith(
        EMAIL,
        PASSWORD,
        expect.any(Array),
        [],
        expect.any(Function),
        customMessage
    )
})

export {}
