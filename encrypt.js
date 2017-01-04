if (process.browser) {
  module.exports = require('./browser/encrypt');
} else {
  module.exports = require('./lib' + '/encrypt');
}
