import cookie from 'cookie';
export interface CsrfProtectOptions {
    cookieName: string;
    headerName: string;
    cookieSerializeOptions: cookie.CookieSerializeOptions;
}
export declare const enableCsrfProtect: (options?: CsrfProtectOptions) => any[];
