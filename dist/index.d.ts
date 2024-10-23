import cookie from 'cookie';
/**
 * Csrf Bypass Config.
 */
export interface CsrfBypassConfig {
    /**
     * The route to check for.
     */
    route?: string;
    /**
     * The HTTP method to check against. If falsy, the check against the request method will be ignored.
     */
    method?: string;
    /**
     * The context to compare the `route` to. This is a property on the express `request` object.
     */
    context?: 'path' | 'url' | 'originalUrl';
    /**
     * The strategy to compare the context against the route with.
     * `exact` means to check if the context matches the route exactly;
     * `prefix` means to check if the context starts with the route.
     */
    strategy?: 'exact' | 'prefix' | 'contains' | 'suffix';
    /**
     * The condition on which this bypass should be considered IF there is a match
     * @returns {booelan}
     */
    onCondition?: (request: any) => boolean;
    /**
     * Calls this method when a request matches a bypass config
     * @returns {booelan}
     */
    onBypass?: () => void;
}
/**
 * Configurations for the CSRF middleware.
 */
export interface CsrfProtectOptions {
    /**
     * Option to override the default cookie name.
     */
    cookieName?: string;
    /**
     * Option to override the default header name
     */
    headerName?: string;
    /**
     * Cookie serialize options. Uses `CookieSerializeOptions` interface from the `cookie` npm library.
     */
    cookieSerializeOptions?: cookie.CookieSerializeOptions;
    /**
     * The HTTP methods to disregard the CSRF with. The default is ['options', 'get', 'head', 'trace'].
     * It is not recommended to set this property with a value-- only do so when configuring bypass routes.
     */
    unprotectedMethods?: string[];
    /**
     * Allows for bypassing certain endpoints.
     */
    bypassConfigs?: Array<CsrfBypassConfig>;
    /**
     * Calls this method when a request does not match a bypass config
     * @returns {booelan}
     */
    onError?: (details: {
        message: string;
    }) => void;
}
export declare const CreateCsrfProtectMiddleware: <T extends boolean, R = T extends true ? any[] : (request: any, response: any, next: any) => any>(options?: CsrfProtectOptions, useCookieParser?: T) => R;
export declare const enableCsrfProtect: (options?: CsrfProtectOptions) => any[];
export declare const useCsrfProtect: (options?: CsrfProtectOptions) => (request: any, response: any, next: any) => any;
