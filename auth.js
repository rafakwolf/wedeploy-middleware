const url = require('url');
const WeDeploy = require('wedeploy');

function assertDefAndNotNull(value, message) {
  if (value === undefined || value === null) {
    throw new Error(message);
  }
}

function assertUserSupportedScopes(user, scopes) {
  if (!user.hasSupportedScopes(scopes)) {
    throw new Error('User does not have scopes: ' + scopes);
  }
}

function extractTokenFromCookie(req) {
  let cookie = req.headers.cookie;
  if (cookie) {
    let value = cookie
      .split(', ')
      .find((p) => p.trim().startsWith('access_token='));

    if (value) {
      return value.substring(13);
    }
  }
}

function extractTokenFromParameter(req) {
  let value = url.parse(req.url, true).query.access_token;
  if (value) {
    return value;
  }
}

function extractAuthorizationFromHeader(req) {
  let value = req.headers && req.headers.authorization;
  if (value) {
    const scheme = value.substring(0, value.indexOf(' ')).trim();
    const header = value.substring(scheme.length + 1).trim();
    switch (scheme) {
      case 'Bearer':
        return {bearer: true, token: header};
      case 'Basic': {
        let [user, pass] = Buffer.from(header, 'base64').toString('utf8').split(':');
        if(user) {
          user = user.toLowerCase();
        }
        return {basic: true, user: user, pass: pass};
      }
    }
  }
}

function handleAuthorizationError(res, config) {
  if (config.redirect) {
    res.writeHead(302, {'Location': config.redirect});
    res.end();
  } else {
    res.writeHead(401, {'Content-Type': 'application/json'});
    res.end(JSON.stringify(config.authorizationError));
  }
}

/**
 * Prepare configuration values.
 * @param  {[type]} config [description]
 */
function prepareConfig(config) {
  if (!('authorizationError' in config)) {
    config.authorizationError = {status: 401, message: 'Unauthorized'};
  }
}

module.exports = function(config) {
  prepareConfig(config);

  assertDefAndNotNull(config, 'WeDeploy configuration must be provided, ' +
    'e.g. { url: \'auth.project.wedeploy.io\' }.');

  assertDefAndNotNull(config.url, 'WeDeploy authentication service url must ' +
    'be provided.');

  return function(req, res, next) {
    let tokenOrEmail = extractTokenFromCookie(req) ||
      extractTokenFromParameter(req);

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

    if (!tokenOrEmail) {
      handleAuthorizationError(res, config);
      return;
    }

    let auth = WeDeploy.auth(config.url);

    auth.verifyUser(tokenOrEmail, password)
      .then((user) => {
        auth.currentUser = user;
        res.locals = res.locals || {};
        res.locals.auth = auth;
        if (config.scopes) {
          assertUserSupportedScopes(user, config.scopes);
        }
        next();
      })
      .catch((reason) => handleAuthorizationError(res, config));
  };
};
