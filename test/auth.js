
const assert = require('assert');
const http = require('http');
const request = require('supertest');
const wedeployMiddleware = require('../');

describe('auth()', function() {
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

  describe('cookies', function() {
    let server;
    before(function() {
      server = createServer().listen(8888);
    });

    after(function() {
      server.close();
    });

    it('should respond as authorized if token present in cookies', function(done) {
      request(server)
        .get('/')
        .set('Cookie', ['access_token=token'])
        .expect(200, done);
    });

    it('should respond as authorized if token present in cookies with multiple values', function(done) {
      request(server)
        .get('/')
        .set('Cookie', ['access_token=token', 'access_token=wrong', 'foo=bar'])
        .expect(200, done);
    });

    it('should respond as unauthorized if token not present in cookies', function(done) {
      request(server)
        .get('/')
        .set('Cookie', ['foo=bar'])
        .expect(401, done);
    });

    it('should respond as authorized if token present in querystring', function(done) {
      request(server)
        .get('/?access_token=token')
        .expect(200, done);
    });

    it('should respond as authorized if token present in headers (Bearer)', function(done) {
      request(server)
        .get('/')
        .set('Authorization', 'Bearer token')
        .expect(200, done);
    });

    it('should respond as authorized if token present in headers (Basic)', function(done) {
      request(server)
        .get('/')
        .set('Authorization', 'Basic dXNlcjpwYXNz')
        .expect(200, done);
    });

    it('should respond as unauthorized if token not present in headers, cookies or querystring', function(done) {
      request(server)
        .get('/')
        .expect(401, done);
    });
  });

  describe('redirect', function() {
    it('should redirect if token not present in headers, cookies or querystring', function(done) {
      let server = createServer('/login').listen(8888);
      request(server)
        .get('/')
        .expect(302, () => {
          server.close();
          done();
        });
    });

    it('should redirect if unauthorized', function(done) {
      let server = createServer('/login', true).listen(8888);
      request(server)
        .get('/')
        .set('Authorization', 'Bearer token')
        .expect(302, () => {
          server.close();
          done();
        });
    });
  });
});

function createServer(errorRedirectUrl = null, respondUserVerificationAsForbidden = false) {
  return http.createServer(function(req, res) {
    switch (req.url) {
      case '/user':
        if (respondUserVerificationAsForbidden) {
          res.statusCode = 403;
          res.end();
        } else {
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({token: 'token'}));
        }
        break;
      default:
        wedeployMiddleware.auth({url: 'http://localhost:8888', redirect: errorRedirectUrl})(req, res, () => res.end());
    }
  });
}
