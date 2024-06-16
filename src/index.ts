import cookie from 'cookie';
import cookieParser from 'cookie-parser';
import { v1 as uuidv1 } from 'uuid';



export interface CsrfProtectOptions {
  cookieName: string,
  headerName: string,
  cookieSerializeOptions: cookie.CookieSerializeOptions,
}

export const enableCsrfProtect = function(options?: CsrfProtectOptions) {
  const sameSiteOptions = [
    'strict',
    'lax',
    'none',
    true,
    false,
  ];

  const csrf_protect_fn = function csrf_protect (request, response, next) {
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

    const useCookieName: string = options && options.hasOwnProperty('cookieName') ? options.cookieName : 'XSRF-TOKEN';
    const useHeaderName: string = options && options.hasOwnProperty('headerName') ? options.headerName : 'X-XSRF-TOKEN';

    const unprotectedCsrfMethods = [
      'options',
      'get',
      'head',
      'trace',
    ];
    const notProtectedMethod = unprotectedCsrfMethods.includes(request.method.toLowerCase());

    if (notProtectedMethod) {
      // no need to validate.
      // check if the request had the cookie. if not, set new one on response.
      const csrfCookie = request.cookies && request.cookies[useCookieName];
      if (!csrfCookie) {
        // taken from: https://www.npmjs.com/package/cookie
        const newCsrfCookie = cookie.serialize(useCookieName, uuidv1(), options ? options.cookieSerializeOptions : {});
        response.setHeader('Set-Cookie', newCsrfCookie);
      }
      return next();
    } else {
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

  return [cookieParser(), csrf_protect_fn];
}