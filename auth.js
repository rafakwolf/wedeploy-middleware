const url = require('url');
const WeDeploy = require('wedeploy');

/**
 * @param {*} value
 * @param {string} message
 */
function assertDefAndNotNull(value, message) {
  if (value === undefined || value === null) {
    throw new Error(message);
  }
}

/**
 * @param {Auth} user
 * @param {Array.<string>} scopes
 */
function assertUserSupportedScopes(user, scopes) {
  if (!user.hasSupportedScopes(scopes)) {
    throw new Error('User does not have scopes: ' + scopes);
  }
}

/**
 * @param {Object} req
 * @return {string}
 */
function extractTokenFromCookie(req) {
  let cookie = req.headers.cookie;
  if (cookie) {
    let value = cookie
      .split('; ')
      .find(p => p.trim().startsWith('access_token='));

    if (value) {
      return decodeURIComponent(value.substring(13));
    }
  }
}

/**
 * @param {Object} req
 * @return {string}
 */
function extractTokenFromParameter(req) {
  let value = url.parse(req.url, true).query.access_token;
  if (value) {
    return value;
  }
}

/**
 * @param {Object} req
 * @return {Object}
 */
function extractAuthorizationFromHeader(req) {
  let value = req.headers && req.headers.authorization;
  if (value) {
    const scheme = value.substring(0, value.indexOf(' ')).trim();
    const header = value.substring(scheme.length + 1).trim();
    switch (scheme) {
      case 'Bearer':
        return {bearer: true, token: header};
      case 'Basic': {
        let [user, pass] = Buffer.from(header, 'base64')
          .toString('utf8')
          .split(':');
        if (user) {
          // Changes user extracted from basic header to lowercase, do not
          // convert to lowercase if extracted value is a JWT token. WeDeploy
          // api supports passing JWT token as user inside basic header,
          // e.g."Authorization: Basic token:". Checking the presence of "@"
          // char on the extracted value is enough to distinguish email or
          // token. JWT tokens are base64 and will never contains "@" char.
          if (user.indexOf('@') >= 0) {
            user = user.toLowerCase();
          }
        }
        return {basic: true, user: user, pass: pass};
      }
    }
  }
}

/**
 * @param {Object} res
 * @param {Object} config
 */
function handleAuthorizationError(res, config) {
  if (config.redirect) {
    res.writeHead(302, {Location: config.redirect});
    res.end();
  } else {
    res.writeHead(401, {'Content-Type': 'application/json'});
    res.end(JSON.stringify(config.authorizationError));
  }
}

/**
 * Prepare configuration values.
 * @param {Object} config
 */
function prepareConfig(config) {
  if (!('authorizationError' in config)) {
    config.authorizationError = {status: 401, message: 'Unauthorized'};
  }
  if (!('unauthorizedOnly' in config)) {
    config.unauthorizedOnly = false;
  }
}

module.exports = function(config) {
  prepareConfig(config);

  assertDefAndNotNull(
    config,
    'WeDeploy configuration must be provided, ' +
      'e.g. { url: \'auth.project.wedeploy.io\' }.'
  );

  assertDefAndNotNull(
    config.url,
    'WeDeploy authentication service url must ' + 'be provided.'
  );

  return function(req, res, next) {
    let tokenOrEmail =
      extractTokenFromCookie(req) || extractTokenFromParameter(req);

    let password;
    if (!tokenOrEmail) {
      let authorization = extractAuthorizationFromHeader(req);
      if (authorization && authorization.bearer) {
        tokenOrEmail = authorization.token;
      } else if (authorization && authorization.basic) {
        tokenOrEmail = authorization.user;
        password = authorization.pass;
      }
    }

    if (config.unauthorizedOnly) {
      if (tokenOrEmail) {
        handleAuthorizationError(res, config);
      }
      next();
      return;
    }

    if (!tokenOrEmail) {
      handleAuthorizationError(res, config);
      return;
    }

    let auth = WeDeploy.auth(config.url);
    auth
      .verifyUser(tokenOrEmail, password)
      .then(user => {
        auth.currentUser = user;
        res.locals = res.locals || {};
        res.locals.auth = auth;
        if (config.scopes) {
          assertUserSupportedScopes(user, config.scopes);
        }
        next();
      })
      .catch(reason => handleAuthorizationError(res, config));
  };
};
