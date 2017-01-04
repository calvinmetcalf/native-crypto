'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var createHmac = require('create-hmac');
var debug = require('debug')('native-crypto:hmac');
var checked = new Map();
var ZERO_BUF = new Buffer(8);
var normalize = require('./normalize');

var bufferEq = require('buffer-equal-constant-time');
var subtle = global.crypto && global.crypto.subtle;
ZERO_BUF.fill(0);
var SIGN = Symbol('sign');
var VERIFY = Symbol('verify');

function checkNative(algo) {
  algo = normalize(algo);
  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  }
  if (!subtle || !subtle.importKey || !subtle.sign || !subtle.verify) {
    return Promise.resolve(false);
  }
  if (checked.has(algo)) {
    return checked.get(algo);
  }
  var prom = subtle.importKey('raw', ZERO_BUF, {
    name: 'HMAC',
    hash: algo
  }, true, ['sign']).then(function (key) {
    return subtle.sign('HMAC', key, ZERO_BUF);
  }).then(function () {
    debug('has working subtle crypto for ' + algo);
    return true;
  }, function (e) {
    debug(e.message);
    return false;
  });
  checked.set(algo, prom);
  return prom;
}

var Hmac = function () {
  function Hmac(algo, key, otherKey) {
    var _this = this;

    _classCallCheck(this, Hmac);

    this.algo = normalize(algo);
    this.key = key;
    if (otherKey) {
      this.other = otherKey;
    } else {
      this.other = false;
    }
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
        _this.nodeCrypto = createHmac(normalize(algo, true), key);
        if (_this._cache && _this._cache.length) {
          _this._cache.forEach(function (thing) {
            _this.nodeCrypto.update(thing);
          });
          _this._cache = null;
        }
      }
    });
  }

  _createClass(Hmac, [{
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
    key: '_final',
    value: function _final(sym) {
      var _this2 = this;

      if (this.other) {
        if (sym !== VERIFY) {
          return Promise.reject(new Error('use verify method'));
        }
      } else {
        if (sym !== SIGN) {
          return Promise.reject(new Error('use digest method'));
        }
      }
      var use;
      if (sym === VERIFY) {
        use = 'verify';
      } else if (sym === SIGN) {
        use = 'sign';
      }
      return this.check.then(function () {
        if (_this2.nodeCrypto) {
          var out = _this2.nodeCrypto.digest();
          if (sym === SIGN) {
            return out;
          } else if (sym === VERIFY) {
            return bufferEq(out, _this2.other);
          }
        }
        var data;
        if (!_this2._cache.length) {
          data = new Buffer('');
        } else if (_this2._cache.length === 1) {
          data = _this2._cache[0];
        } else {
          data = Buffer.concat(_this2._cache);
        }
        return subtle.importKey('raw', _this2.key, {
          name: 'HMAC',
          hash: _this2.algo
        }, true, [use]).then(function (key) {
          _this2.key = null;
          if (sym === SIGN) {
            return subtle.sign('HMAC', key, data).then(function (buf) {
              return new Buffer(buf);
            });
          } else if (sym === VERIFY) {
            return subtle.verify('HMAC', key, _this2.other, data);
          }
        });
      });
    }
  }, {
    key: 'digest',
    value: function digest() {
      return this._final(SIGN);
    }
  }, {
    key: 'verify',
    value: function verify() {
      return this._final(VERIFY);
    }
  }]);

  return Hmac;
}();

module.exports = Hmac;