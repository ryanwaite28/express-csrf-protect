"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.useCsrfProtect = exports.enableCsrfProtect = exports.CreateCsrfProtectMiddleware = void 0;
const cookie_1 = __importDefault(require("cookie"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const uuid_1 = require("uuid");
const CreateCsrfProtectMiddleware = function (options, useCookieParser) {
    const useCookieSerializeOptions = !!options && !!options.cookieSerializeOptions
        ? Object.assign({}, options && options.cookieSerializeOptions) : {};
    const unprotectedCsrfMethods = (options && options.unprotectedMethods) ? options.unprotectedMethods : [
        'options',
        'get',
        'head',
        'trace',
    ];
    const useCookieName = !!options && !!options.cookieName ? options.cookieName : 'XSRF-TOKEN';
    const useHeaderName = !!options && !!options.headerName ? options.headerName : 'X-XSRF-TOKEN';
    const checkShouldBypass = (request) => {
        const hasBypassConfigs = !!options && !!options.bypassConfigs && !!options.bypassConfigs.length;
        if (!hasBypassConfigs) {
            return false;
        }
        const bypassConfigs = options.bypassConfigs;
        /*
          Check if the request matches any of the bypass configs
        */
        for (const bypassConfig of bypassConfigs) {
            // check the onCondition
            // check if config has a method to check against and if it matches the request method
            if (!!bypassConfig.method && bypassConfig.method.toLowerCase() !== request.method.toLowerCase()) {
                // the config had a method specified but did not match the request method; continue to next config
                continue;
            }
            const match = (() => {
                if (!bypassConfig.context || !bypassConfig.route) {
                    return false;
                }
                switch (bypassConfig.strategy) {
                    case 'exact':
                        return request[bypassConfig.context] === bypassConfig.route;
                    case 'prefix':
                        return request[bypassConfig.context].startsWith(bypassConfig.route);
                    case 'contains':
                        return request[bypassConfig.context].includes(bypassConfig.route);
                    case 'suffix':
                        return request[bypassConfig.context].endsWith(bypassConfig.route);
                }
            })();
            const conditionApplies = !bypassConfig.onCondition || bypassConfig.onCondition(request);
            if (match && conditionApplies) {
                if (bypassConfig.onBypass) {
                    bypassConfig.onBypass(request, bypassConfig);
                }
                return true;
            }
        }
        return false;
    };
    const csrf_protect_fn = function csrf_protect(request, response, next) {
        const notProtectedMethod = unprotectedCsrfMethods.includes(request.method.toLowerCase());
        if (notProtectedMethod) {
            // no need to validate. check if the request had the cookie. if not, set new one on response.
            const csrfCookie = request.cookies && request.cookies[useCookieName];
            if (!csrfCookie) {
                // taken from: https://www.npmjs.com/package/cookie
                const newCsrfCookie = cookie_1.default.serialize(useCookieName, (0, uuid_1.v4)(), useCookieSerializeOptions);
                response.setHeader('Set-Cookie', newCsrfCookie);
            }
            return next();
        }
        else {
            // check if this is a request to bypass
            const shouldBypass = checkShouldBypass(request);
            if (shouldBypass) {
                return next();
            }
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
    const middleware = useCookieParser ? [(0, cookie_parser_1.default)(), csrf_protect_fn] : csrf_protect_fn;
    return middleware;
};
exports.CreateCsrfProtectMiddleware = CreateCsrfProtectMiddleware;
const enableCsrfProtect = (options) => (0, exports.CreateCsrfProtectMiddleware)(options, true);
exports.enableCsrfProtect = enableCsrfProtect;
const useCsrfProtect = (options) => (0, exports.CreateCsrfProtectMiddleware)(options, false);
exports.useCsrfProtect = useCsrfProtect;
//# sourceMappingURL=index.js.map