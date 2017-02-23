'use strict';

var aes = require('browserify-aes');
var debug = require('debug')('native-crypto:decrypt');
var check = null;
var ZERO_BUF = new Buffer(16);
ZERO_BUF.fill(0);
var TEST_BUFFER = new Buffer('A4jazmC2o5LzKMK5cbL+ePeVqqtJS1kj9/2J/5SLweAgAhEhTnOU2iCJtqzQk6vgyU2iGRGOKX17fry8ycOI8p7MWbwdPpusE+GvoYsO2TE=', 'base64');
var subtle = global.crypto && global.crypto.subtle;

function checkNative() {

  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  } else {
    if (!subtle || !subtle.importKey || !subtle.encrypt) {
      return Promise.resolve(false);
    }
    if (check) {
      return check;
    }
    check = subtle.importKey('raw', ZERO_BUF, {
      name: 'AES-GCM'
    }, true, ['decrypt']).then(function (key) {
      return subtle.decrypt({
        name: 'AES-GCM',
        iv: ZERO_BUF.slice(0, 12),
        additionalData: ZERO_BUF.slice(0, 8)
      }, key, TEST_BUFFER);
    }).then(function (res) {
      if (new Buffer(res).toString('base64') === 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==') {
        debug('has working subtle crypto for aes-gcm');
        return true;
      } else {
        debug('decrypted incorectly');
        return false;
      }
    }, function (e) {
      debug('not using subtle crypto', e);
      return false;
    });
    return check;
  }
}
module.exports = decrypt;

function decrypt(key, iv, cipherText, aad) {
  if (typeof plainText === 'string') {
    cipherText = new Buffer(cipherText);
  }

  return checkNative().then(function (res) {
    if (res) {
      var opts = {
        name: 'AES-GCM',
        iv: iv
      };
      if (aad) {
        opts.additionalData = aad.buffer;
      }
      return subtle.importKey('raw', key, {
        name: 'AES-GCM'
      }, true, ['decrypt']).then(function (key) {
        return subtle.decrypt(opts, key, cipherText);
      }).then(function (resp) {
        return new Buffer(resp);
      });
    } else {
      var algo = getAlgo(key);
      var cipher = aes.createDecipheriv(algo, key, iv);
      if (aad) {
        cipher.setAAD(aad);
      }
      var tag = cipherText.slice(-16);
      cipherText = cipherText.slice(0, -16);
      cipher.setAuthTag(tag);
      var output = cipher.update(cipherText);
      cipher.final();
      return output;
    }
  });
}

function getAlgo(key) {
  switch (key.length) {
    case 16:
      return 'aes-128-gcm';
    case 24:
      return 'aes-192-gcm';
    case 32:
      return 'aes-256-gcm';
    default:
      throw new TypeError('invalid key size');
  }
}