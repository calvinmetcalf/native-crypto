if (process.browser) {
  module.exports = require('./browser/decrypt');
} else {
  module.exports = require('./lib' + '/decrypt');
}
