import cookie from 'cookie';
import cookieParser from 'cookie-parser';
import { v4 as uuidv4 } from 'uuid';


/**
 * Csrf Bypass Config.
 */
export interface CsrfBypassConfig {
  /**
   * The route to check for.
   */
  route?: string,

  /**
   * The HTTP method to check against. If falsy, the check against the request method will be ignored.
   */
  method?: string,

  /**
   * The context to compare the `route` to. This is a property on the express `request` object.
   */
  context?: 'path' | 'url' | 'originalUrl',

  /**
   * The strategy to compare the context against the route with. 
   * `exact` means to check if the context matches the route exactly;
   * `prefix` means to check if the context starts with the route.
   */
  strategy?: 'exact' | 'prefix' | 'contains' | 'suffix',

  /**
   * The condition on which this bypass should be considered IF there is a match
   * @returns {booelan}
   */
  onCondition?: (request) => boolean,

  /**
   * Calls this method when a request matches a bypass config
   * @returns {booelan}
   */
  onBypass?: () => void,
}


/**
 * Configurations for the CSRF middleware.
 */
export interface CsrfProtectOptions {
  /**
   * Option to override the default cookie name.
   */
  cookieName?: string,

  /**
   * Option to override the default header name
   */
  headerName?: string,

  /**
   * Cookie serialize options. Uses `CookieSerializeOptions` interface from the `cookie` npm library.
   */
  cookieSerializeOptions?: cookie.CookieSerializeOptions,

  /**
   * The HTTP methods to disregard the CSRF with. The default is ['options', 'get', 'head', 'trace']. 
   * It is not recommended to set this property with a value-- only do so when configuring bypass routes.
   */
  unprotectedMethods?: string[];

  /**
   * Allows for bypassing certain endpoints.
   */
  bypassConfigs?: Array<CsrfBypassConfig>,

  /**
   * Calls this method when a request fails CSRF validation
   * @returns {booelan}
   */
  onError?: (details: {
    message: string
  }) => void,

  /**
   * Calls this method when a request passes CSRF validation
   * @returns {booelan}
   */
  onSuccess?: () => void,
}

export const CreateCsrfProtectMiddleware = function<T extends boolean, R = T extends true ? (any[]) : (request, response, next) => any>(options?: CsrfProtectOptions, useCookieParser?: T): R {

  console.log(`CSRF protection - options:`, options);

  const useCookieSerializeOptions = !!options && !!options.cookieSerializeOptions
    ? { ...options && options.cookieSerializeOptions }
    : {}

  const unprotectedCsrfMethods = (options && options.unprotectedMethods) ? options.unprotectedMethods : [
    'options',
    'get',
    'head',
    'trace',
  ];

  console.log("Using unprotected http methods:", unprotectedCsrfMethods)

  const useCookieName: string = !!options && !!options.cookieName ? options.cookieName : 'XSRF-TOKEN';
  const useHeaderName: string = !!options && !!options.headerName ? options.headerName : 'X-XSRF-TOKEN';

  const checkShouldBypass = (request) => {
    const hasBypassConfigs: boolean = !!options && !!options.bypassConfigs && !!options.bypassConfigs.length;
    if (!hasBypassConfigs) {
      return false;
    }

    const bypassConfigs = options!.bypassConfigs!;

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

      const match: boolean = (() => {
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

      const conditionApplies: boolean = !bypassConfig.onCondition || bypassConfig.onCondition(request);

      if (match && conditionApplies) {
        bypassConfig.onBypass && bypassConfig.onBypass();
        return true;
      }
    }

    return false;
  };


  const csrf_protect_fn = function csrf_protect (request, response, next) {

    const notProtectedMethod = unprotectedCsrfMethods.includes(request.method.toLowerCase());

    if (notProtectedMethod) {
      // no need to validate. check if the request had the cookie. if not, set new one on response.
      const csrfCookie = request.cookies && request.cookies[useCookieName];
      if (!csrfCookie) {
        // taken from: https://www.npmjs.com/package/cookie
        const newCsrfCookie = cookie.serialize(useCookieName, uuidv4(), useCookieSerializeOptions);
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
        const errorMessage = `forbidden: cookie with name "${useCookieName}" is not found in request`;
        if (options && options.onError) {
          options.onError({
            message: errorMessage
          });
        }
        return response.status(403).json({
          message: errorMessage
        });
      }

      const csrfHeader = request.get(useHeaderName);
      if (!csrfHeader) {
        // no header found
        const errorMessage = `forbidden: header with name "${useHeaderName}" is not found in request`;
        if (options && options.onError) {
          options.onError({
            message: errorMessage
          });
        }
        return response.status(403).json({
          message: errorMessage,
        });
      }

      const doesNotMatch = csrfCookie !== csrfHeader;
      if (doesNotMatch) {
        const errorMessage = `forbidden: header with name "${useHeaderName}" does not match cookie with name "${useCookieName}"`;
        if (options && options.onError) {
          options.onError({
            message: errorMessage
          });
        }
        // both found but does not match
        return response.status(403).json({
          message: errorMessage
        });
      }

      // successfully validated.
      if (options && options.onSuccess) {
        options.onSuccess();
      }
      return next();
    }
  };

  const middleware = useCookieParser ? [cookieParser(), csrf_protect_fn] : csrf_protect_fn;
  return middleware as R;
}

export const enableCsrfProtect = (options?: CsrfProtectOptions) => CreateCsrfProtectMiddleware(options, true);

export const useCsrfProtect = (options?: CsrfProtectOptions) => CreateCsrfProtectMiddleware(options, false);
