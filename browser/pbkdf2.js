'use strict';

var normalize = require('./normalize');
var debug = require('debug')('native-crypto:pbkdf2');

var checks = new Map();
var ZERO_BUF = new Buffer(8);
var compat = require('pbkdf2');
var subtle = global.crypto && global.crypto.subtle;
ZERO_BUF.fill(0);

function checkNative(algo) {
  algo = normalize(algo);
  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  }
  if (!subtle || !subtle.importKey || !subtle.deriveBits) {
    return Promise.resolve(false);
  }
  if (checks.has(algo)) {
    return checks.get(algo);
  }
  var prom = browserPbkdf2(ZERO_BUF, ZERO_BUF, 10, 128, algo).then(function () {
    debug('working pbkf2 with ' + algo);
    return true;
  }).catch(function () {
    debug('no pbkf2 with ' + algo);
    return false;
  });
  checks.set(algo, prom);
  return prom;
}

module.exports = pbkdf2;

function pbkdf2(password, salt, iterations, length, algo) {
  return checkNative(algo).then(function (res) {
    if (typeof password === 'string') {
      password = new Buffer(password, 'utf8');
    }
    if (res) {
      return browserPbkdf2(password, salt, iterations, length, algo);
    }
    var alg = normalize(algo, true);
    return new Promise(function (success, failure) {
      compat.pbkdf2(password, salt, iterations, length, alg, function (err, res) {
        if (err) {
          return failure(err);
        }
        success(res);
      });
    });
  });
}

function browserPbkdf2(password, salt, iterations, length, algo) {
  return subtle.importKey('raw', password, {
    name: 'PBKDF2'
  }, false, ['deriveBits']).then(function (key) {
    return subtle.deriveBits({
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: {
        name: normalize(algo)
      }
    }, key, length << 3);
  }).then(function (res) {
    return new Buffer(res);
  });
}