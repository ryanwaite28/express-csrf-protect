const cookie = require('cookie');
const { v1: uuidv1 } = require('uuid');

exports.enable = function(options) {
  const sameSiteOptions = [
    'strict',
    'lax',
    'none',
    true,
    false,
  ];

  const csrf_protect_fn = function csrf_protect (request, response, next) {
    const useOptions = {
      cookieName: options && options.cookieName || 'XSRF-TOKEN',
      headerName: options && options.headerName || 'X-XSRF-TOKEN',
      path: options && options.path || '/',
      signed: options && !!options.signed || false,
      secure: options && !!options.secure || false,
      expires: options && options.expires,
      maxAge: options && options.maxAge,
      httpOnly: options && !!options.httpOnly || false,
      sameSite: options && sameSiteOptions.includes(options.sameSite) && options.sameSite || 'none',
      domain: options && (
        options.useGivenDomain
          ? options.domain
          : (options.domain || request.get('host'))
      ),
    };

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
      const csrfCookie = request.cookies && request.cookies[useOptions.cookieName];
      if (!csrfCookie) {
        // taken from: https://www.npmjs.com/package/cookie
        const newCsrfCookie = cookie.serialize(useOptions.cookieName, uuidv1(), {
          path: useOptions.path,
          signed: useOptions.signed,
          secure: useOptions.secure,
          expires: useOptions.expires,
          maxAge: useOptions.maxAge,
          httpOnly: useOptions.httpOnly,
          sameSite: useOptions.sameSite,
          domain: useOptions.domain,
        });
        response.setHeader('Set-Cookie', newCsrfCookie);
      }
      return next();
    } else {
      // this is a protected request method, validate cookie and header
      const csrfCookie = request.cookies && request.cookies[useOptions.cookieName];
      if (!csrfCookie) {
        // no cookie found
        return response.status(403).json({
          message: `forbidden: cookie with name "${useOptions.cookieName}" is not found in request`
        });
      }
      const csrfHeader = request.get(useOptions.headerName);
      if (!csrfHeader) {
        // no header found
        return response.status(403).json({
          message: `forbidden: header with name "${useOptions.headerName}" is not found in request`
        });
      }
      const doesNotMatch = csrfCookie !== csrfHeader;
      if (doesNotMatch) {
        // both found but does not match
        return response.status(403).json({
          message: `forbidden: header with name "${useOptions.headerName}" does not match cookie with name "${useOptions.cookieName}"`
        });
      }

      // successfully validated.
      return next();
    }
  };

  return csrf_protect_fn;
}