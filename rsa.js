if (process.browser) {
  module.exports = require('./browser/rsa');
} else {
  module.exports = require('./lib' + '/rsa');
}
