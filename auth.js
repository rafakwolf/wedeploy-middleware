const url = require('url');
const WeDeploy = require('wedeploy');

function assertDefAndNotNull(value, message) {
  if (value === undefined || value === null) {
    throw new Error(message);
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

function extractTokenFromHeader(req) {
  let value = req.headers && req.headers.authorization;
  if (value) {
    const scheme = value.substring(0, value.indexOf(' ')).trim();
    const header = value.substring(scheme.length + 1).trim();
    switch (scheme) {
      case 'Bearer':
        return header;
      case 'Basic':
        return Buffer.from(header, 'base64').toString('utf8');
    }
  }
}

function verifyUserJwtToken(token, config) {
  return WeDeploy.auth(config.url).verifyUser(token);
}

function handleAuthorizationError(res, config) {
  if (config.redirect) {
    res.writeHead(302, {'Location': config.redirect});
  } else {
    res.statusCode = 401;
  }
  res.end();
}

module.exports = function(config) {
  assertDefAndNotNull(config, 'WeDeploy configuration must be provided, ' +
    'e.g. { url: \'auth.project.wedeploy.io\' }.');

  assertDefAndNotNull(config.url, 'WeDeploy authentication service url must ' +
    'be provided.');

  return function(req, res, next) {
    let token = extractTokenFromHeader(req) ||
      extractTokenFromCookie(req) ||
      extractTokenFromParameter(req);

    if (!token) {
      handleAuthorizationError(res, config);
      return;
    }

    verifyUserJwtToken(token, config)
      .then((user) => {
        res.locals = res.locals || {};
        res.locals.user = user;
        next();
      })
      .catch((reason) => handleAuthorizationError(res, config));
  };
};
