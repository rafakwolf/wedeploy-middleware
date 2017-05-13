# wedeploy-middleware

[![Build Status](https://travis-ci.org/wedeploy/wedeploy-middleware.svg?branch=master)](https://travis-ci.org/wedeploy/wedeploy-middleware)
[![npm version](https://badge.fury.io/js/wedeploy-middleware.svg)](https://badge.fury.io/js/wedeploy-middleware)

## Auth
Node.js middleware to help users to authenticate using passwords, popular federated identity providers like Google, Facebook, GitHub, and more using [WeDeploy™ Auth](http://wedeploy.com/docs/auth/).

**How it works** - For every request intercepted by the auth middleware a token or credential may be extracted in the following order:

| Source                        | Key                                                                   |
| ----------------------------- | --------------------------------------------------------------------- |
| Basic Authentication          | `curl -u "username:password" "https://api.wedeploy.io/"`              |
| OAuth2 Token (header)         | `curl -H "Authorization: Bearer TOKEN" "https://api.wedeploy.io/"`    |
| OAuth2 Token (query string)   | `curl "https://api.wedeploy.io/?access_token=TOKEN"`                  |
| OAuth2 Token (cookie)         | `curl -H "Cookie:access_token=TOKEN" "https://api.wedeploy.io/"`      |

## Installation

```sh
$ npm install wedeploy-middleware
```

## API

```js
var express = require('express');
var wedeployMiddleware = require('wedeploy-middleware');

var app = express();
app.use(wedeployMiddleware.auth({url: 'auth.project.wedeploy.io'}));
```

### wedeployMiddleware.auth(options)

- `options.url` authorization service url passed to `WeDeploy.auth(url)`.
- `options.redirect` optional url to redirect on authentication failure, e.g. `/login`.
- `options.scopes` optional authorization scopes.
- `options.authorizationError` optional authorization error response body, e.g. `{status: 401, message: 'Unauthorized'}`.
- `options.unauthorizedOnly` optional check ensuring that there's no logged user for the current route, e.g. `true`.

## Examples

### Basic usage

```js
var express = require('express');
var wedeployMiddleware = require('wedeploy-middleware');

var app = express();
app.use(wedeployMiddleware.auth({url: 'auth.project.wedeploy.io'}));

app.get('/private', function(req, res) {
  // User that has been signed in
  console.log('User: ', res.locals.auth.currentUser);
});

app.listen(8080);
```

### Authenticating with scopes

```js
var express = require('express');
var wedeployMiddleware = require('wedeploy-middleware');

var app = express();

var authMiddleware = wedeployMiddleware.auth({
  url: 'auth.project.wedeploy.io',
  scopes: ['superuser', 'manager']
});

app.get('/admin', authMiddleware, function(req, res) {
  // User that has been signed in
  console.log('User: ', res.locals.auth.currentUser);
});

app.listen(8080);
```


```js
// curl http://localhost:8080/private -H 'Authorization: Bearer token' -v
// curl http://localhost:8080/private -H 'Authorization: Basic dXNlcjpwYXNz' -v
```

### [MIT Licensed](LICENSE)
