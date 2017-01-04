'use strict';
const normalize = require('./normalize');
const debug = require('debug')('native-crypto:pbkdf2');

const checks = new Map();
const ZERO_BUF = new Buffer(8);
const compat = require('pbkdf2');
const subtle = global.crypto && global.crypto.subtle;
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
  let prom = browserPbkdf2(ZERO_BUF, ZERO_BUF, 10, 128, algo)
    .then(() => {
      debug(`working pbkf2 with ${algo}`);
      return true;
    }).catch(() => {
      debug(`no pbkf2 with ${algo}`);
      return false;
    });
  checks.set(algo, prom);
  return prom;
}

module.exports = pbkdf2;

function pbkdf2(password, salt, iterations, length, algo) {
  return checkNative(algo).then(res => {
    if (typeof password === 'string') {
      password = new Buffer(password, 'utf8');
    }
    if (res) {
      return browserPbkdf2(password, salt, iterations, length, algo);
    }
    let alg = normalize(algo, true);
    return new Promise((success, failure) => {
      compat.pbkdf2(password, salt, iterations, length, alg, (err, res) => {
        if (err) {
          return failure(err);
        }
        success(res);
      });
    });
  });
}

function browserPbkdf2(password, salt, iterations, length, algo) {
  return subtle.importKey(
    'raw', password, {
      name: 'PBKDF2'
    }, false, ['deriveBits']
  ).then(key => subtle.deriveBits({
    name: 'PBKDF2',
    salt: salt,
    iterations: iterations,
    hash: {
      name: normalize(algo)
    }
  }, key, length << 3)).then(res => new Buffer(res));
}
