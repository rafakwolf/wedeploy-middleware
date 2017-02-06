# wedeploy-middleware

[![Build Status](https://travis-ci.org/wedeploy/wedeploy-middleware.svg?branch=master)](https://travis-ci.org/wedeploy/wedeploy-middleware)
[![npm version](https://badge.fury.io/js/wedeploy-middleware.svg)](https://badge.fury.io/js/wedeploy-middleware)

## Auth
Node.js middleware to help users to authenticate using passwords, popular federated identity providers like Google, Facebook, GitHub, and more using [WeDeploy™ Auth](http://wedeploy.com/docs/auth/).

**How it works** - For every request intercepted by the auth middleware a token may be extracted in the following order:
From `Authorization: Bearer token` or `Authorization: Basic dXNlcjpwYXNz` headers, then if not founds it checks for `access_token` cookie or query parameter.

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

## Example

```js
var express = require('express');
var wedeployMiddleware = require('wedeploy-middleware');

var app = express();
app.use(wedeployMiddleware.auth({url: 'auth.project.wedeploy.io'}));

app.get('/private', function(req, res) {
  // User that has been signed in
  console.log('User: ', res.locals.user);
});

app.listen(8080);
```

```js
// curl http://localhost:8080/private -H 'Authorization: Bearer token' -v
// curl http://localhost:8080/private -H 'Authorization: Basic dXNlcjpwYXNz' -v
```

### [MIT Licensed](LICENSE)
