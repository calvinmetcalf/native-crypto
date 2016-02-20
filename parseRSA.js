const asn1 = require('asn1.js');
const base64url = require('./base64url');
module.exports = parseRSA;
module.exports.parsePublic = parsePublic;
module.exports.parsePrivate = parsePrivate;
function parsePublic(publicKey) {
  const parsedPublic = RSAPublicKey.decode(publikKey, 'der');
  return {
     kty: 'RSA',
     n: base64url.encode(parsedPublic.n),
     e: base64url.encode(parsedPublic.e),
     key_ops: ['verify'],
     ext: true
  };
}
function parsePrivate(privateKey) {
  const parsedPrivate = RSAPrivateKey.decode(privateKey, 'der');
  return {
     kty: 'RSA',
     n: base64url.encode(parsedPrivate.n),
     e: base64url.encode(parsedPrivate.e),
     d: base64url.encode(parsedPrivate.d),
     p: base64url.encode(parsedPrivate.p),
     q: base64url.encode(parsedPrivate.q),
     dp: base64url.encode(parsedPrivate.dp),
     dq: base64url.encode(parsedPrivate.dq),
     qi: base64url.encode(parsedPrivate.qi),
     key_ops: ['sign'],
     ext: true
  };
}
function parseRSA(pair) {
  return {
    publicKey: parsePublic(pair.publicKey),
    privateKey: parsePrivate(pair.privateKey)
  };
}
const RSAPrivateKey = asn1.define('RSAPrivateKey', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('n').int(),
    this.key('e').int(),
    this.key('d').int(),
    this.key('p').int(),
    this.key('q').int(),
    this.key('dp').int(),
    this.key('dq').int(),
    this.key('qi').int()
  )
})

const RSAPublicKey = asn1.define('RSAPublicKey', function () {
  this.seq().obj(
    this.key('n').int(),
    this.key('e').int()
  )
})
