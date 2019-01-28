const url = require('url');
const WeDeploy = require('wedeploy');
const util = require('util');
const ns = 'wedeploy-auth-middleware-redis';

module.exports = {};
/**
 * Turn async function into regular function
 * @param  {Function} fn
 * @return {Function}
 */
function awaitFunction(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

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
 * @param {Object} config
 */
function assertUserSupportedScopes(user, config) {
  let foundScopes = true;
  const {scopes, scopesOr} = config;
  if (scopesOr) {
    if (user.supportedScopes) {
      foundScopes = scopes.some(scope => user.supportedScopes.includes(scope));
    }
  } else {
    foundScopes = user.hasSupportedScopes(scopes);
  }
  if (!foundScopes) {
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
 * @param {Object} next
 * @param {Object} config
 */
function handleAuthorizationError(res, next, config) {
  if (config.redirect) {
    res.writeHead(302, {Location: config.redirect});
    res.end();
  } else {
    if (config.authorizationError === false) {
      next();
      return;
    }
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

/**
 * Get User from Redis Client
 * @param  {!Response} res
 * @param  {!Auth} auth
 * @param  {!string} tokenOrEmail
 * @param  {!Object} config
 * @return {Auth}
 */
async function retrieveUserFromRedis(res, auth, tokenOrEmail, config) {
  if (config.redisClient) {
    const getFromRedis = util
      .promisify(config.redisClient.get)
      .bind(config.redisClient);
    const cachedUserData = await getFromRedis(`${ns}:${tokenOrEmail}`);
    if (cachedUserData) {
      const data = JSON.parse(cachedUserData);
      const user = auth.createAuthFromData(data);
      auth.currentUser = user;
      res.locals = res.locals || {};
      res.locals.auth = auth;
      return user;
    }
  }
}

/**
 * Save user in Redis Client
 * @param  {!Auth} user
 * @param  {!String} tokenOrEmail
 * @param  {!Object} config
 */
function saveUserInRedis(user, tokenOrEmail, config) {
  if (config.redisClient) {
    const key = `${ns}:${tokenOrEmail}`;
    config.redisClient.set(key, JSON.stringify(user.data_), 'EX', 10);
  }
}

/**
 * Delete user in Redis Client
 * @param  {!String} tokenOrEmail
 * @param  {!Object} config
 */
module.exports.deleteUserInRedis = function(tokenOrEmail, config) {
  if (config.redisClient) {
    const key = `${ns}:${tokenOrEmail}`;
    config.redisClient.del(key);
  }
};

/**
 * Auth middleware
 * @param {Object} config
 * @param {Object} config.authorizationError
 * @param {String} config.redirect
 * @param {String[]} config.scopes
 * @param {Boolean} config.unauthorizedOnly
 * @param {String} config.url
 * @param {Function} config.verifyUser(req, res) - An alternative way
    to retrieve the auth user. Can be async.
 * @param {RedisClient} config.redisClient
 * @return {Auth} - stores auth user in res.locals.auth.currentUser
 */
module.exports.auth = function(config) {
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

  return awaitFunction(async function(req, res, next) {
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

    // If route requires unauthorized only validation and there is no token
    // or email, it goes to the next middleware.
    if (config.unauthorizedOnly) {
      if (!tokenOrEmail) {
        next();
        return;
      }
    }
    if (!tokenOrEmail && !config.verifyUser) {
      handleAuthorizationError(res, next, config);
      return;
    }

    const auth = WeDeploy.auth(config.url);

    const user = await retrieveUserFromRedis(res, auth, tokenOrEmail, config);
    if (user) {
      if (config.unauthorizedOnly) {
        handleAuthorizationError(res, next, config);
        next();
        return;
      }
      if (config.scopes) {
        assertUserSupportedScopes(user, config);
      }
      next();
      return;
    }

    let verifyUserPromise;

    if (config.verifyUser) {
      verifyUserPromise = Promise.resolve(config.verifyUser(req, res));
    } else if (tokenOrEmail && password) {
      verifyUserPromise = auth.signInWithEmailAndPassword(
        tokenOrEmail,
        password
      );
    } else {
      verifyUserPromise = auth.verifyUser(tokenOrEmail);
    }

    verifyUserPromise
      .then(user => {
        // If route requires unauthorized only validation
        // and token or email is valid, it should redirect
        // to route specified on config or throw an error.
        if (config.unauthorizedOnly) {
          handleAuthorizationError(res, next, config);
          next();
          return;
        }
        if (config.scopes) {
          assertUserSupportedScopes(user, config);
        }
        auth.currentUser = user;
        res.locals = res.locals || {};
        res.locals.auth = auth;
        saveUserInRedis(user, tokenOrEmail, config);
        next();
      })
      .catch(reason => {
        // If route requires unauthorized only validation
        // and token or email is invalid, it means the user
        // is unauthorized, therefore goes to the next
        // middleware.
        if (config.unauthorizedOnly) {
          next();
          return;
        }
        handleAuthorizationError(res, next, config);
      });
  });
};
