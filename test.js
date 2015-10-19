'use strict';
if (process.browser) {
  window.myDebug = require('debug');
  window.myDebug.enable('native-crypto:*');
}
var crypto = require('crypto');
var test = require('tape');
var Hash = require('./hash');
var Hmac = require('./hmac');
var encrypt = require('./encrypt');
var decrypt = require('./decrypt');
test('hash', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  var nodeHash = crypto.createHash('sha256').update(buf).digest().toString('hex');
  new Hash('sha-256').update(buf).digest().then(function (ourHash) {
    t.equals(nodeHash, ourHash.toString('hex'));
    t.end();
  }).catch(function (e) {
    t.ok(false, e.stack);
    t.end();
  });
});
test('hmac sign', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  var nodeHash = crypto.createHmac('sha256', buf).update(buf).digest().toString('hex');
  new Hmac('sha-256', buf).update(buf).digest().then(function (ourHash) {
    t.equals(nodeHash, ourHash.toString('hex'), 'worked');
    t.end();
  }).catch(function (e) {
    t.ok(false, e.stack);
    t.end();
  });
});
test('hmac verify', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  var nodeHash = crypto.createHmac('sha256', buf).update(buf).digest();
  new Hmac('sha-256', buf, nodeHash).update(buf).verify().then(function (ourHash) {
    t.ok(ourHash, 'worked');
    t.end();
  }).catch(function (e) {
    t.ok(false, e.stack);
    t.end();
  });
});
test('encrypt/decrypt', function (t) {
  var key = new Buffer(16);
  var iv = new Buffer(12);
  var aad = new Buffer(8);
  var data = new Buffer(64);
  key.fill(0);
  iv.fill(0);
  aad.fill(0);
  data.fill(0);
  var nodeCipher = crypto.createCipheriv('aes-128-gcm', key, iv);
  nodeCipher.setAAD(aad);
  var out = nodeCipher.update(data);
  nodeCipher.final();
  var tag = nodeCipher.getAuthTag();
  var expected = Buffer.concat([out, tag]).toString('hex');
  encrypt(key, iv, data, aad).then(function (res) {
    t.equals(res.toString('hex'), expected, 'encrypted');
    return decrypt(key, iv, res, aad);
  }).then(function (res) {
    t.equals(res.toString('hex'), data.toString('hex'), 'decrypted');
    t.end();
  }).catch(function (e) {
    t.error(e);
    t.end();
  });
});
