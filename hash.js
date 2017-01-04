if (process.browser) {
  module.exports = require('./browser/hash');
} else {
  module.exports = require('./lib' + '/hash');
}
