const assert = require('assert');
const http = require('http');
const request = require('supertest');
const wedeployMiddleware = require('../');

let currentUser;

describe('wedeploy-middleware', () => {
  beforeEach(() => {
    currentUser = null;
  });

  describe('.auth()', function() {
    it('should export auth function', function() {
      assert(typeof wedeployMiddleware.auth, 'function');
    });

    it('should throws exception if configuration not specified', function() {
      assert.throws(() => {
        wedeployMiddleware.auth();
      }, Error);
    });

    it('should throws exception if authentication service url not specified', function() {
      assert.throws(() => {
        wedeployMiddleware.auth({});
      }, Error);
    });

    it('should not throw exception if authentication service url specified', function() {
      assert.doesNotThrow(() => {
        wedeployMiddleware.auth({url: ''});
      });
    });
  });

  describe('cookies', function() {
    it('should respond as authorized if token present in cookies', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set('Cookie', 'access_token=token')
        .end((err, res) => {
          assert.strictEqual(currentUser.token, 'token');
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should respond as authorized if token present in cookies with multiple values', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set('Cookie', 'foo=bar; access_token=token; access_token=wrong')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should respond as authorized if token present in cookies has special characters', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set('Cookie', `access_token=${encodeURIComponent('token=4i=')}`)
        .end((err, res) => {
          assert.strictEqual(currentUser.token, 'token=4i=');
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should respond as unauthorized if token not present in cookies', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set('Cookie', 'foo=bar')
        .end((err, res) => {
          assert.strictEqual(401, res.statusCode);
          server.close(() => done());
        });
    });

    it('should respond as authorized if token is invalid but route requires unauthorized only', function(
      done
    ) {
      let server = createServer(null, true).listen(8999);
      request(server)
        .get('/guest')
        .set('Cookie', 'access_token=invalidtoken')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });
  });

  describe('querystring', function() {
    it('should respond as authorized if token present in querystring', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/?access_token=token')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });
  });

  describe('headers', function() {
    it('should respond as authorized if token present in headers (Bearer)', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer token')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should respond as authorized if credentials are present in headers (Basic)', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set(
          'Authorization',
          `Basic ${Buffer.from('user@domain.com:pass').toString('base64')}`
        )
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          assert.strictEqual('user@domain.com', currentUser.email);
          server.close(() => done());
        });
    });

    it('should convert to lowercase value extracted from authorization header if it\'s an email (Basic)', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set(
          'Authorization',
          `Basic ${Buffer.from('USER@domain.com:pass').toString('base64')}`
        )
        .end((err, res) => {
          assert.strictEqual('user@domain.com', currentUser.email);
          server.close(() => done());
        });
    });

    it('should not convert to lowercase value extracted from authorization header if it\'s a token (Basic)', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set(
          'Authorization',
          `Basic ${Buffer.from('TOKEN:').toString('base64')}`
        )
        .end((err, res) => {
          assert.strictEqual('TOKEN', currentUser.token);
          server.close(() => done());
        });
    });

    it('should respond as authorized if unknown authorization scheme', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Unknown token')
        .end((err, res) => {
          assert.strictEqual(401, res.statusCode);
          server.close(() => done());
        });
    });

    it('should redirect if unauthorized', function(done) {
      let server = createServer('/login', true).listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer skipRedirectBecauseTokenWasMissing')
        .end((err, res) => {
          assert.strictEqual(302, res.statusCode);
          server.close(() => done());
        });
    });
  });

  describe('token presence', function() {
    it('should respond as unauthorized if token not present in headers, cookies or querystring', function(
      done
    ) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .end((err, res) => {
          assert.strictEqual(401, res.statusCode);
          server.close(() => done());
        });
    });

    it('should redirect if token not present in headers, cookies or querystring', function(
      done
    ) {
      let server = createServer('/login').listen(8999);
      request(server)
        .get('/')
        .end((err, res) => {
          assert.strictEqual(302, res.statusCode);
          server.close(() => done());
        });
    });
  });

  describe('scopes', function() {
    it('should redirect if scope is invalid', function(done) {
      let server = createServer('/login', false, ['invalidScope']).listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer skipRedirectBecauseTokenWasMissing')
        .end((err, res) => {
          assert.strictEqual(302, res.statusCode);
          server.close(() => done());
        });
    });

    it('should not redirect if scope is valid', function(done) {
      let server = createServer('/login', false, ['validScope']).listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer skipRedirectBecauseTokenWasMissing')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should not redirect if scope is not specified', function(done) {
      let server = createServer('/login').listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer skipRedirectBecauseTokenWasMissing')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should not authorize if scope is invalid', function(done) {
      let server = createServer(null, false, ['invalidScope']).listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer skipRedirectBecauseTokenWasMissing')
        .end((err, res) => {
          assert.strictEqual(401, res.statusCode);
          server.close(() => done());
        });
    });

    it('should authorize if scope is valid', function(done) {
      let server = createServer(null, false, ['validScope']).listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer skipRedirectBecauseTokenWasMissing')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should authorize if scope is not specified', function(done) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer skipRedirectBecauseTokenWasMissing')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });
  });

  describe('config.authorizationError', function() {
    it('should output default authorization error', function(done) {
      let server = createServer().listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Unknown token')
        .end((err, res) => {
          assert.deepEqual({status: 401, message: 'Unauthorized'}, res.body);
          server.close(() => done());
        });
    });

    it('should output custom authorization error', function(done) {
      let server = createServer(null, false, null, 'doNotEnter').listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Unknown token')
        .end((err, res) => {
          assert.deepEqual('doNotEnter', res.body);
          server.close(() => done());
        });
    });

    it('should proceed to the next middleware and not throw an error if authorizationError is false', function(
      done
    ) {
      let server = createServer(null, false, null, false).listen(8999);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer token')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });
  });

  describe('config.unauthorizedOnly', function() {
    it('should redirect if request has authenticated user', function(done) {
      let server = createServer('/authorized-route', false).listen(8999);
      request(server)
        .get('/guest')
        .set('Authorization', 'Bearer authorizedToken')
        .end((err, res) => {
          assert.strictEqual(302, res.statusCode);
          assert.strictEqual('/authorized-route', res.headers.location);
          server.close(() => done());
        });
    });
    it('should not redirect if request does not have authenticated user', function(
      done
    ) {
      let server = createServer('/authorized-route', false).listen(8999);
      request(server)
        .get('/guest')
        .end((err, res) => {
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });
  });

  describe('config.verifyUser', function() {
    it('overrides the default auth.verifyUser', function(done) {
      const verifyUser = (req, res) => 'anotherUser';
      let server = createServer(
        null,
        false,
        null,
        undefined,
        verifyUser
      ).listen(8999);
      request(server)
        .get('/verify')
        .end((err, res) => {
          assert.strictEqual(currentUser, 'anotherUser');
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('can be an async method', function(done) {
      const verifyUser = (req, res) => {
        return new Promise(resolve => {
          setTimeout(() => resolve('asyncUser'), 1);
        });
      };
      let server = createServer(
        null,
        false,
        null,
        undefined,
        verifyUser
      ).listen(8999);
      request(server)
        .get('/verify')
        .end((err, res) => {
          assert.strictEqual(currentUser, 'asyncUser');
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });
  });

  describe('config.redisClient', function() {
    let exampleClient = {};
    const ns = 'wedeploy-auth-middleware-redis';
    let setKey;

    before(() => {
      exampleClient.get = (key, callback) => {
        if (key === `${ns}:token`) {
          return callback(undefined, `{"email": "redis@liferay.com"}`);
        } else {
          return callback(undefined);
        }
      };
      exampleClient.set = (key, value) => {
        setKey = key;
      };
    });

    it('should get user from client cache with correct token', done => {
      let server = createServer(
        null,
        false,
        null,
        undefined,
        undefined,
        exampleClient
      ).listen(8999);
      request(server)
        .get('/redis')
        .set('Cookie', 'access_token=token')
        .end((err, res) => {
          assert.strictEqual(currentUser.email, 'redis@liferay.com');
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should not fail when user token is not in client cache', done => {
      let server = createServer(
        null,
        false,
        null,
        undefined,
        undefined,
        exampleClient
      ).listen(8999);
      request(server)
        .get('/redis')
        .set('Cookie', 'access_token=uncachedToken1')
        .end((err, res) => {
          assert.strictEqual(currentUser.token, 'uncachedToken1');
          assert.strictEqual(
            setKey,
            'wedeploy-auth-middleware-redis:uncachedToken1'
          );
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });

    it('should set correct token in client cache', done => {
      let server = createServer(
        null,
        false,
        null,
        undefined,
        undefined,
        exampleClient
      ).listen(8999);
      request(server)
        .get('/redis')
        .set('Cookie', 'access_token=uncachedToken2')
        .end((err, res) => {
          assert.strictEqual(
            setKey,
            'wedeploy-auth-middleware-redis:uncachedToken2'
          );
          assert.strictEqual(200, res.statusCode);
          server.close(() => done());
        });
    });
  });
});

function createServer(
  errorRedirectUrl = null,
  respondUserVerificationAsForbidden = false,
  scopes = null,
  authorizationError,
  verifyUser,
  redisClient
) {
  return http.createServer(function(req, res) {
    switch (req.url) {
      case '/user': {
        if (respondUserVerificationAsForbidden) {
          res.statusCode = 403;
          res.end();
        } else {
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              token: 'token',
              supportedScopes: ['validScope'],
              email: 'user@domain.com',
            })
          );
        }
        break;
      }
      case '/oauth/token?grant_type=password&username=user%40domain.com&password=pass': {
        if (respondUserVerificationAsForbidden) {
          res.statusCode = 403;
          res.end();
        } else {
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({access_token: 'token'}));
        }
        break;
      }
      case '/guest': {
        let config = {
          url: 'http://localhost:8999',
          redirect: errorRedirectUrl,
          unauthorizedOnly: true,
        };
        let authMiddleware = wedeployMiddleware.auth(config);
        authMiddleware(req, res, () => {
          res.end();
        });
        break;
      }
      case '/verify': {
        let config = {
          url: 'http://localhost:8999',
          verifyUser: verifyUser,
        };
        let authMiddleware = wedeployMiddleware.auth(config);
        authMiddleware(req, res, () => {
          currentUser = res.locals.auth.currentUser;
          res.end();
        });
        break;
      }
      case '/redis': {
        let config = {
          url: 'http://localhost:8999',
          redisClient,
        };
        let authMiddleware = wedeployMiddleware.auth(config);
        authMiddleware(req, res, () => {
          currentUser = res.locals.auth.currentUser;
          res.end();
        });
        break;
      }
      default: {
        let config = {
          url: 'http://localhost:8999',
          redirect: errorRedirectUrl,
          scopes: scopes,
        };
        if (authorizationError !== undefined) {
          config.authorizationError = authorizationError;
        }
        let authMiddleware = wedeployMiddleware.auth(config);
        authMiddleware(req, res, err => {
          currentUser = res.locals.auth.currentUser;
          res.end();
        });
      }
    }
  });
}
