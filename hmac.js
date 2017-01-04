if (process.browser) {
  module.exports = require('./browser/hmac');
} else {
  module.exports = require('./lib' + '/hmac');
}
