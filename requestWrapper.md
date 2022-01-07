## Request Wrapper is an abstractive function that helps to write better req,res with TDD approach.

```ts
import { AxiosInstance, AxiosResponse, AxiosRequestConfig, Method } from 'axios'

type AxiosRequestFunc = <T = any, R = AxiosResponse<T>>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig
) => Promise<R>

export type StatusCodeErrorMap = Map<number, string>

export type RequestWrapperOptions<T_Params, T_Payload, T_Result> = {
    method: Method
    url: (options: T_Params) => string
    statusCodeSuccess: number
    statusCodeErrorMap: StatusCodeErrorMap
    fallbackError: string
    toPayload: (payload: T_Params) => T_Payload
    toHeaders?: (payload: T_Params) => Record<string, string>
    parseResponse: (data: any) => T_Result
}

export const requestWrapper =
    <T_Params, T_Payload, T_Result>(
        axios: AxiosInstance,
        options: RequestWrapperOptions<T_Params, T_Payload, T_Result>
    ) =>
    async (params: T_Params): Promise<T_Result> => {
        const request = getAxiosRequestFuncByMethod(axios, options.method)

        const payload = options.toPayload(params)

        const headers = options.toHeaders ? options.toHeaders(params) : null

        const response = await request(options.url(params), payload, {
            headers,
        })

        if (response.status === options.statusCodeSuccess) {
            return options.parseResponse(response.data)
        }

        if (!options.statusCodeErrorMap.has(response.status)) {
            throw new Error(options.fallbackError)
        }

        throw new Error(options.statusCodeErrorMap.get(response.status))
    }

const getAxiosRequestFuncByMethod = (
    axios: AxiosInstance,
    method: Method
): AxiosRequestFunc => {
    if (method === 'GET') {
        return axios.get
    }

    if (method === 'POST') {
        return axios.post
    }

    throw new Error(`Failed to get axios request function for ${method}.`)
}

export const fixedUrl =
    <T>(url: string) =>
    (_params: T) =>
        url

```
