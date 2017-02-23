'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var createHash = require('create-hash');
var sign = require('browserify-sign');
var debug = require('debug')('native-crypto:signature');
var checked = new Map();
var normalize = require('./normalize');
var ZERO_BUF = new Buffer(16);
ZERO_BUF.fill(0);
var jwk2pem = require('jwk-to-pem');
var SIGN = Symbol('sign');
var VERIFY = Symbol('verify');
var base64url = require('./base64url');
var KEY = {};
var raw = null;
var elliptic = require('elliptic');
var EC = elliptic.ec;
var format = require('ecdsa-sig-formatter');
var fromDer = format.derToJose;
var toDer = format.joseToDer;
var subtle = global.crypto && global.crypto.subtle;
function checkNative(type, algo, curve) {
  algo = normalize(algo);
  if (curve) {
    curve = normalize(curve);
  }
  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  }
  if (!subtle || !subtle.importKey || !subtle.sign || !subtle.verify) {
    return Promise.resolve(false);
  }
  var id = algo + '-' + type + '-' + curve;
  if (checked.has(id)) {
    return checked.get(id);
  }
  var opts = {
    name: type
  };
  if (curve) {
    opts.namedCurve = curve;
  } else {
    opts.modulusLength = 1024;
    opts.publicExponent = new Buffer([0x01, 0x00, 0x01]);
    opts.hash = {
      name: algo
    };
  }
  var signOpts = {
    name: type
  };
  if (curve) {
    signOpts.hash = {
      name: algo
    };
  }
  var prom = subtle.generateKey(opts, false, ['sign']).then(function (key) {
    return subtle.sign(signOpts, key.privateKey, ZERO_BUF);
  }).then(function () {
    debug('has working sublte crypto for type: ' + type + ' with digest ' + algo + ' ' + (curve ? '\n      with curve: ' + curve + '\n      ' : ''));
    return true;
  }, function (e) {
    debug(e.message);
    return false;
  });
  checked.set(algo, prom);
  return prom;
}
var lens = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66
};
var ecNames = {
  'P-256': 'p256',
  'P-384': 'p384',
  'P-521': 'p521'
};
var otherECNames = {
  'P-256': 'ES256',
  'P-384': 'ES384',
  'P-521': 'ES512'
};

var Signature = function () {
  function Signature(key, otherKey) {
    var _this = this;

    _classCallCheck(this, Signature);

    if (key.kty && key.kty.toLowerCase() === 'rsa') {
      this.type = 'RSASSA-PKCS1-v1_5';
      this.curve = null;
    } else if (key.kty && key.kty.toLowerCase() === 'ec') {
      this.type = 'ECDSA';
      this.curve = normalize(key.crv);
    }
    if (this.curve) {
      switch (this.curve) {
        case 'P-256':
          this.algo = 'SHA-256';
          break;
        case 'P-384':
          this.algo = 'SHA-384';
          break;
        case 'P-521':
          this.algo = 'SHA-512';
          break;
      }
    } else if (key.alg) {
      this.algo = normalize(key.alg);
    } else {
      throw new Error('invalid key');
    }
    this._key = new WeakMap();
    this._key.set(KEY, key);
    if (otherKey) {
      this.other = otherKey;
    } else {
      this.other = false;
    }
    this.hasNative = void 0;
    this.checking = true;
    this._cache = [];
    this.nodeCrypto = null;
    this.check = checkNative(this.type, this.algo, this.curve).then(function (answer) {
      _this.checking = false;
      if (answer) {
        _this.hasNative = true;
      } else {
        _this.hasNative = false;
        var algo = normalize(_this.algo, true);
        if (_this.curve) {
          _this.nodeCrypto = createHash(algo);
        } else if (_this.other) {
          _this.nodeCrypto = sign.createVerify('RSA-' + algo);
        } else {
          _this.nodeCrypto = sign.createSign('RSA-' + algo);
        }
        if (_this._cache && _this._cache.length) {
          _this._cache.forEach(function (thing) {
            _this.nodeCrypto.update(thing);
          });
          _this._cache = null;
        }
      }
    });
  }

  _createClass(Signature, [{
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
        var key = _this2._key.get(KEY);
        if (_this2.nodeCrypto) {
          if (sym === SIGN) {
            if (!_this2.curve) {
              return _this2.nodeCrypto.sign(jwk2pem(key, {
                private: true
              }));
            }
            var hash = _this2.nodeCrypto.digest();
            if (raw) {
              var signKey = new raw.Key(new Buffer(jwk2pem(key, {
                private: true
              })));
              return new Buffer(fromDer(signKey.sign(hash), otherECNames[_this2.curve]), 'base64');
            }
            var ec = new EC(ecNames[_this2.curve]);
            var keyPair = ec.keyFromPrivate(base64url.decode(key.d));
            var sig = keyPair.sign(hash);
            var r = new Buffer(sig.r.toArray());
            var s = new Buffer(sig.s.toArray());
            var len = lens[_this2.curve];
            while (r.length < len) {
              r = Buffer.concat([new Buffer([0]), r]);
            }
            while (s.length < len) {
              s = Buffer.concat([new Buffer([0]), s]);
            }
            return Buffer.concat([r, s]);
          } else if (sym === VERIFY) {
            if (!_this2.curve) {
              return _this2.nodeCrypto.verify(jwk2pem(key), _this2.other);
            }
            var other = toDer(_this2.other, otherECNames[_this2.curve]);

            var _hash = _this2.nodeCrypto.digest();
            if (raw) {
              var ver = new raw.Key(new Buffer(jwk2pem(key)));
              return ver.verify(other, _hash);
            }
            var _ec = new EC(ecNames[_this2.curve]);
            return _ec.verify(_hash, other, {
              x: base64url.decode(key.x).toString('hex'),
              y: base64url.decode(key.y).toString('hex')
            });
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
        var importOpts = {
          name: _this2.type
        };
        var signOpts = {
          name: _this2.type
        };
        if (_this2.curve) {
          importOpts.namedCurve = _this2.curve;
          signOpts.hash = {
            name: _this2.algo
          };
        } else {
          importOpts.hash = {
            name: _this2.algo
          };
        }

        return subtle.importKey('jwk', key, importOpts, true, [use]).then(function (key) {
          _this2.key = null;
          if (sym === SIGN) {
            return subtle.sign(signOpts, key, data).then(function (buf) {
              return new Buffer(buf);
            });
          } else if (sym === VERIFY) {
            return subtle.verify(signOpts, key, _this2.other, data);
          }
        });
      });
    }
  }, {
    key: 'sign',
    value: function sign() {
      return this._final(SIGN);
    }
  }, {
    key: 'verify',
    value: function verify() {
      return this._final(VERIFY);
    }
  }], [{
    key: 'generateKey',
    value: function generateKey(type, len, algo) {
      return subtle.generateKey({
        name: type,
        modulusLength: len,
        publicExponent: new Buffer([0x01, 0x00, 0x01]),
        hash: {
          name: algo
        }
      }, true, ['sign', 'verify']).then(function (key) {
        return subtle.exportKey('jwk', key);
      });
    }
  }]);

  return Signature;
}();

module.exports = Signature;