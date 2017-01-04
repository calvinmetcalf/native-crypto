'use strict';
const pubLens = new Map([
  ['P-256', 32],
  ['P-384', 48],
  ['P-521', 66]
]);
const base64url = require('./base64url');

const FOUR_BUFFER = new Buffer([4]);
exports.fromJwk = fromJwk;
function fromJwk(jwk) {
  return Buffer.concat([FOUR_BUFFER, base64url.decode(jwk.x), base64url.decode(jwk.y)]);
}
exports.toJwk = toJwk;
function toJwk(buf, type) {
  buf = buf.slice(1);
  let len = pubLens.get(type);
  let jwk = {
    kty: 'EC',
    crv: type,
    x: base64url.encode(buf.slice(0, len)),
    y: base64url.encode(buf.slice(len)),
    ext: true
  };
  return jwk;
}
