"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.enableCsrfProtect = void 0;
const cookie_1 = __importDefault(require("cookie"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const uuid_1 = require("uuid");
const enableCsrfProtect = function (options) {
    const sameSiteOptions = [
        'strict',
        'lax',
        'none',
        true,
        false,
    ];
    const csrf_protect_fn = function csrf_protect(request, response, next) {
        // const host: string = request.get('host') || '';
        // const useDomain: string = !options ? host : options && (
        //   options.useGivenDomain
        //     ? options.domain
        //     : (
        //         options.domain || (
        //           host.includes('localhost')
        //             ? ''
        //             : host
        //         )
        //       )
        // );
        const useCookieName = !!options && !!options.cookieName ? options.cookieName : 'XSRF-TOKEN';
        const useHeaderName = !!options && !!options.headerName ? options.headerName : 'X-XSRF-TOKEN';
        const unprotectedCsrfMethods = [
            'options',
            'get',
            'head',
            'trace',
        ];
        const notProtectedMethod = unprotectedCsrfMethods.includes(request.method.toLowerCase());
        const useCookieSerializeOptions = !!options && !!options.cookieSerializeOptions
            ? Object.assign({}, options && options.cookieSerializeOptions) : {};
        if (notProtectedMethod) {
            // no need to validate.
            // check if the request had the cookie. if not, set new one on response.
            const csrfCookie = request.cookies && request.cookies[useCookieName];
            if (!csrfCookie) {
                // taken from: https://www.npmjs.com/package/cookie
                const newCsrfCookie = cookie_1.default.serialize(useCookieName, (0, uuid_1.v1)(), useCookieSerializeOptions);
                response.setHeader('Set-Cookie', newCsrfCookie);
            }
            return next();
        }
        else {
            // this is a protected request method, validate cookie and header
            const csrfCookie = request.cookies && request.cookies[useCookieName];
            if (!csrfCookie) {
                // no cookie found
                return response.status(403).json({
                    message: `forbidden: cookie with name "${useCookieName}" is not found in request`
                });
            }
            const csrfHeader = request.get(useHeaderName);
            if (!csrfHeader) {
                // no header found
                return response.status(403).json({
                    message: `forbidden: header with name "${useHeaderName}" is not found in request`
                });
            }
            const doesNotMatch = csrfCookie !== csrfHeader;
            if (doesNotMatch) {
                // both found but does not match
                return response.status(403).json({
                    message: `forbidden: header with name "${useHeaderName}" does not match cookie with name "${useCookieName}"`
                });
            }
            // successfully validated.
            return next();
        }
    };
    return [(0, cookie_parser_1.default)(), csrf_protect_fn];
};
exports.enableCsrfProtect = enableCsrfProtect;
//# sourceMappingURL=index.js.map