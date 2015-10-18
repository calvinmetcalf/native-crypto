'use strict';

var crypto = require('crypto');
var test = require('tape');
var Hash = require('./hash');
var Hmac = require('./hmac');
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
  })
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
  })
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
  })
});
