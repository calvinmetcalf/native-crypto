'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var createHash = require('create-hash');
var normalize = require('./normalize');
var debug = require('debug')('native-crypto:hash');
var checked = new Map();
var ZERO_BUF = new Buffer(8);
var subtle = global.crypto && global.crypto.subtle;
ZERO_BUF.fill(0);

function checkNative(algo) {
  algo = normalize(algo);
  if (!subtle || !subtle.digest) {
    return Promise.resolve(false);
  }
  if (checked.has(algo)) {
    return checked.get(algo);
  }
  var prom = subtle.digest(algo, ZERO_BUF).then(function () {
    debug('has working subtle crypto for ' + algo);
    return true;
  }, function () {
    return false;
  });
  checked.set(algo, prom);
  return prom;
}

var Hash = function () {
  function Hash(algo) {
    var _this = this;

    _classCallCheck(this, Hash);

    this.algo = normalize(algo);
    this.hasNative = void 0;
    this.checking = true;
    this._cache = [];
    this.nodeCrypto = null;
    this.check = checkNative(algo).then(function (answer) {
      _this.checking = false;
      if (answer) {
        _this.hasNative = true;
      } else {
        _this.hasNative = false;
        _this.nodeCrypto = createHash(normalize(algo, true));
        if (_this._cache && _this._cache.length) {
          _this._cache.forEach(function (thing) {
            _this.nodeCrypto.update(thing);
          });
          _this._cache = null;
        }
      }
    });
  }

  _createClass(Hash, [{
    key: 'update',
    value: function update(data) {
      if (this.nodeCrypto) {
        this.nodeCrypto.update(data);
      } else if (this._cache) {
        this._cache.push(data);
      } else {
        throw new Error('should be imposible to get here');
      }
      return this;
    }
  }, {
    key: 'digest',
    value: function digest() {
      var _this2 = this;

      return this.check.then(function () {
        if (_this2.nodeCrypto) {
          var out = _this2.nodeCrypto.digest();
          return out;
        }
        var data;
        if (!_this2._cache.length) {
          data = new Buffer('');
        } else if (_this2._cache.length === 1) {
          data = _this2._cache[0];
        } else {
          data = Buffer.concat(_this2._cache);
        }
        return subtle.digest(_this2.algo, data).then(function (buf) {
          return new Buffer(buf);
        });
      });
    }
  }]);

  return Hash;
}();

module.exports = Hash;