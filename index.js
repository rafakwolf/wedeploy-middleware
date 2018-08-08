const wedeployMiddleware = require('./auth');

module.exports = {
  auth: wedeployMiddleware.auth,
  deleteUserInRedis: wedeployMiddleware.deleteUserInRedis,
};
