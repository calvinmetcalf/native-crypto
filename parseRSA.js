const asn1 = require('asn1.js');
const base64url = require('./base64url');
var pemstrip = require('pemstrip');
module.exports = parseRSA;
module.exports.parsePublic = parsePublic;
module.exports.parsePrivate = parsePrivate;
function parsePublic(publicKey) {
  const striped = pemstrip.strip(publicKey);
  const parsedPublic1 = PublicKey.decode(new Buffer(striped.base64, 'base64'), 'der');
  const parsedPublic = RSAPublicKey.decode(parsedPublic1.subjectPublicKey.data, 'der')
  return {
     kty: 'RSA',
     n: base64url.encode(parsedPublic.n.toBuffer()),
     e: base64url.encode(parsedPublic.e.toBuffer()),
     key_ops: ['verify'],
     ext: true
  };
}
function parsePrivate(privateKey) {
  const striped = pemstrip.strip(privateKey);
  const parsedPrivate = RSAPrivateKey.decode(new Buffer(striped.base64, 'base64'), 'der');
  return {
     kty: 'RSA',
     n: base64url.encode(parsedPrivate.n.toBuffer()),
     e: base64url.encode(parsedPrivate.e.toBuffer()),
     d: base64url.encode(parsedPrivate.d.toBuffer()),
     p: base64url.encode(parsedPrivate.p.toBuffer()),
     q: base64url.encode(parsedPrivate.q.toBuffer()),
     dp: base64url.encode(parsedPrivate.dp.toBuffer()),
     dq: base64url.encode(parsedPrivate.dq.toBuffer()),
     qi: base64url.encode(parsedPrivate.qi.toBuffer()),
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
var PublicKey = asn1.define('SubjectPublicKeyInfo', function () {
  this.seq().obj(
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('subjectPublicKey').bitstr()
  )
})

var AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function () {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('none').null_().optional(),
    this.key('curve').objid().optional(),
    this.key('params').seq().obj(
      this.key('p').int(),
      this.key('q').int(),
      this.key('g').int()
    ).optional()
  )
})
