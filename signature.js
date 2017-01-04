if (process.browser) {
  module.exports = require('./browser/signature');
} else {
  module.exports = require('./lib' + '/signature');
}
