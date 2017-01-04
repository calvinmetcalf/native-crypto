'use strict';

var pubLens = new Map([['P-256', 32], ['P-384', 48], ['P-521', 66]]);
var base64url = require('./base64url');

var FOUR_BUFFER = new Buffer([4]);
exports.fromJwk = fromJwk;
function fromJwk(jwk) {
  return Buffer.concat([FOUR_BUFFER, base64url.decode(jwk.x), base64url.decode(jwk.y)]);
}
exports.toJwk = toJwk;
function toJwk(buf, type) {
  buf = buf.slice(1);
  var len = pubLens.get(type);
  var jwk = {
    kty: 'EC',
    crv: type,
    x: base64url.encode(buf.slice(0, len)),
    y: base64url.encode(buf.slice(len)),
    ext: true
  };
  return jwk;
}