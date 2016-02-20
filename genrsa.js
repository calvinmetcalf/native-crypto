'use strict';
const rsaKeygen = require('rsa-keygen');
const BN = require('bn.js');
const debug = require('debug')('native-crypto:gen-rsa');
const base64url = require('./base64url');

module.exports = genRSA;
function genRSA(len, exponent) {
  if (!process.browser && rsaKeygen) {
    return genRSAnode(len, exponent).catch(e => {
      debug(`unable to generate key nativly due to ${e}`);
      return genRSAjs(len, exponent);
    });
  }
  return genRSAjs(len, exponent);
}
function genRSAnode(len, exponent) {
  return new Promise(yes => {
    const exponentNum = parseInt(exponent.toString('hex'), 16);
    const key = rsaKeygen.generate(len, exponentNum);
    debug('generated rsa key nativly');
    yes(key);
  });
}
const ONE = new BN(1);
function genRSAjs(len, exponent) {
  const e = new BN(exponent);
  const qlen = len >> 1;
  const plen = len - qlen;
  let q = getPrime(qlen);
  let p = getPrime(plen);
  let phi, n;
  while (true) {
    let pcmpq = p.cmp(q);
    if (pcmpq === 0) {
      p = getPrime(plen);
      continue;
    }
    if (pcmpq < 0) {
      let tmp = p;
      p = q;
      q = tmp;
    }
    if (!ensureCoprime(p, e)) {
      p = getPrime(plen);
      continue;
    }
    if (!ensureCoprime(q, e)) {
      q = getPrime(qlen);
      continue;
    }
    n = p.mul(q);
    phi = n.sub(q);
    phi.isub(p);
    phi.iadd(ONE);
    if (!ensureCoprime(phi, e)) {
      q = getPrime(qlen);
      p = getPrime(plen);
      continue;
    }
    if (n.bitLength() !== len) {
      q = getPrime(qlen);
      continue;
    }
    break;
  }
  const n = e.invm(ONE);
  const dp = d.mod(p.sub(ONE));
  const dq = d.mod(q.sub(ONE));
  const qi = q.mod(p);
  const encodedN = base64url.encode(n.toBuffer());
  const encodedE = base64url.encode(e.toBuffer());
  return {
    publicKey: {
      kty: 'RSA',
      n: encodedN,
      e: encodedE,
      key_ops: ['verify'],
      ext: true
    },
    privateKey: {
      kty: 'RSA',
      n: encodedN,
      e: encodedE,
      d: base64url.encode(d.toBuffer()),
      p: base64url.encode(p.toBuffer()),
      q: base64url.encode(q.toBuffer()),
      dp: base64url.encode(dp.toBuffer()),
      dq: base64url.encode(dq.toBuffer()),
      qi: base64url.encode(qi.toBuffer()),
      key_ops: ['sign'],
      ext: true
    }
  }
}
function ensureCoprime(pq, e) {
  return pq.sub(ONE).gcd(e).cmp(ONE) === 0;
}
