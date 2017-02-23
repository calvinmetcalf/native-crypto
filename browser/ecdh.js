'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var createECDH = require('create-ecdh');
var debug = require('debug')('native-crypto:ecdh');
var normalize = require('./normalize');
var checked = new Map();
var KEYS = {};
var jwk = require('./jwk');
var base64url = require('./base64url');
var secLens = new Map([['P-256', 256], ['P-384', 384], ['P-521', 520]]);
var subtle = global.crypto && global.crypto.subtle;

function checkNative(algo) {
  algo = normalize(algo);
  if (!subtle || !subtle.generateKey || !subtle.deriveBits) {
    return Promise.resolve(false);
  }
  if (checked.has(algo)) {
    return checked.get(algo);
  }
  var prom = Promise.all([subtle.generateKey({
    name: 'ecdh',
    namedCurve: algo
  }, true, ['deriveBits']), subtle.generateKey({
    name: 'ecdh',
    namedCurve: algo
  }, true, ['deriveBits'])]).then(function (resp) {
    var pub1 = resp[0].publicKey;
    var pub2 = resp[1].publicKey;
    var priv1 = resp[0].privateKey;
    var priv2 = resp[1].privateKey;
    var outLen = secLens.get(algo);
    return Promise.all([subtle.deriveBits({
      name: 'ecdh',
      namedCurve: algo,
      public: pub1
    }, priv2, outLen), subtle.deriveBits({
      name: 'ecdh',
      namedCurve: algo,
      public: pub2
    }, priv1, outLen), subtle.exportKey('jwk', priv1)]).then(function (resp) {
      if (new Buffer(resp[0]).toString('base64') === new Buffer(resp[1]).toString('base64')) {
        debug('has working ecdh with curve ' + algo);
        return true;
      } else {
        debug('results did not match for curve ' + algo);
        return false;
      }
    }).catch(function (e) {
      debug('non working subtle crypto for curve ' + algo + ' due to error ' + e);
      return false;
    });
  });
  checked.set(algo, prom);
  return prom;
}

var ECDH = function () {
  function ECDH(curve, priv) {
    var _this = this;

    _classCallCheck(this, ECDH);

    this.curve = normalize(curve);
    this.hasNative = void 0;
    this.checking = true;
    this._map = new WeakMap();
    this.check = checkNative(curve).then(function (answer) {
      _this.checking = false;
      if (answer) {
        _this.hasNative = true;
        var makeKeys = void 0;
        if (priv) {
          var pub = {};
          Object.keys(priv).forEach(function (key) {
            if (key !== 'd') {
              pub[key] = priv[key];
            }
          });
          makeKeys = Promise.all([subtle.importKey('jwk', priv, {
            name: 'ecdh',
            namedCurve: _this.curve
          }, true, ['deriveBits']), subtle.importKey('jwk', pub, {
            name: 'ecdh',
            namedCurve: _this.curve
          }, true, [])]).then(function (resp) {
            return {
              privateKey: resp[0],
              publicKey: resp[1]
            };
          });
        } else {
          makeKeys = subtle.generateKey({
            name: 'ecdh',
            namedCurve: _this.curve
          }, true, ['deriveBits']);
        }
        return makeKeys.then(function (resp) {
          _this._map.set(KEYS, resp);
        });
      } else {
        _this.hasNative = false;
        var nodeCrypto = createECDH(normalize(curve, true));
        nodeCrypto.generateKeys();
        _this._map.set(KEYS, nodeCrypto);
        if (priv) {
          nodeCrypto.setPrivateKey(base64url.decode(priv.d));
          nodeCrypto.setPublicKey(jwk.fromJwk(priv));
        }
      }
    });
  }

  _createClass(ECDH, [{
    key: 'getPublic',
    value: function getPublic() {
      var _this2 = this;

      return this.check.then(function () {
        var pair = _this2._map.get(KEYS);
        if (_this2.hasNative) {
          return subtle.exportKey('jwk', pair.publicKey);
        } else {
          return jwk.toJwk(pair.getPublicKey(), _this2.curve);
        }
      });
    }
  }, {
    key: 'getPrivate',
    value: function getPrivate() {
      var _this3 = this;

      return this.check.then(function () {
        var pair = _this3._map.get(KEYS);
        if (_this3.hasNative) {
          return subtle.exportKey('jwk', pair.privateKey);
        } else {
          var out = jwk.toJwk(pair.getPublicKey(), _this3.curve);
          out.d = base64url.encode(pair.getPrivateKey());
          return out;
        }
      });
    }
  }, {
    key: 'computeSecret',
    value: function computeSecret(publicKey) {
      var _this4 = this;

      return this.check.then(function () {
        return Promise.resolve(publicKey);
      }).then(function (publicKey) {
        var pair = _this4._map.get(KEYS);
        if (_this4.hasNative) {
          return subtle.importKey('jwk', publicKey, {
            name: 'ecdh',
            namedCurve: _this4.curve
          }, true, []).then(function (key) {
            return subtle.deriveBits({
              name: 'ecdh',
              namedCurve: _this4.curve,
              public: key
            }, pair.privateKey, secLens.get(_this4.curve));
          }).then(function (res) {
            return new Buffer(res);
          });
        } else {
          return pair.computeSecret(jwk.fromJwk(publicKey));
        }
      });
    }
  }]);

  return ECDH;
}();

module.exports = ECDH;