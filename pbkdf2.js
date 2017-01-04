if (process.browser) {
  module.exports = require('./browser/pbkdf2');
} else {
  module.exports = require('./lib' + '/pbkdf2');
}
