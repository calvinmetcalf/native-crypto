if (process.browser) {
  module.exports = require('./browser/generate');
} else {
  module.exports = require('./lib' + '/generate');
}
