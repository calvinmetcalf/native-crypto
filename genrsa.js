'use strict';
const rsaKeygen = require('rsa-keygen');
const BN = require('bn.js');
const debug = require('debug')('native-crypto:gen-rsa');
const base64url = require('./base64url');
const randomBytes = require('randombytes');
const ONE = new BN(1);
const TWO = new BN(2);
const MillerRabin = require('miller-rabin');
const parseRSA = require('./parseRSA');
const co = require('co');
let millerRabin;
module.exports = genRSA;
const genRSAjs = co.wrap(_genRSAjs);
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
    yes(parseRSA({
      publicKey: key.public_key,
      privateKey: key.private_key
    }));
  });
}
const getPrime = co.wrap(_getPrime);
function *  _genRSAjs(len, exponent) {
  const e = new BN(exponent);
  const qlen = len >> 1;
  const plen = len - qlen;
  let q = yield getPrime(qlen);
  let p = yield getPrime(plen);
  let phi, n;
  while (true) {
    let pcmpq = p.cmp(q);
    if (pcmpq === 0) {
      p = yield getPrime(plen);
      continue;
    }
    if (pcmpq < 0) {
      let tmp = p;
      p = q;
      q = tmp;
    }
    if (!ensureCoprime(p, e)) {
      p = yield getPrime(plen);
      continue;
    }
    if (!ensureCoprime(q, e)) {
      q = yield getPrime(qlen);
      continue;
    }
    n = p.mul(q);
    phi = n.sub(q);
    phi.isub(p);
    phi.iadd(ONE);
    if (!ensureCoprime(phi, e)) {
      q = yield getPrime(qlen);
      p = yield getPrime(plen);
      continue;
    }
    if (n.bitLength() !== len) {
      q = yield getPrime(qlen);
      continue;
    }
    break;
  }
  const d = e.invm(phi);
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
  };
}
function ensureCoprime(pq, e) {
  return pq.sub(ONE).gcd(e).cmp(ONE) === 0;
}
var primes = null;

function _getPrimes() {
  if (primes !== null)
    return primes;

  const limit = 0x100000;
  const res = [];
  res[0] = 2;
  let j;
  for (let i = 1, k = 3; k < limit; k += 2) {
    let sqrt = Math.ceil(Math.sqrt(k));
    for (j = 0; j < i && res[j] <= sqrt; j++)
      if (k % res[j] === 0)
        break;

    if (i !== j && res[j] <= sqrt)
      continue;

    res[i++] = k;
  }
  primes = res;
  return res;
}

function simpleSieve(p) {
  var primes = _getPrimes();

  for (let i = 0; i < primes.length; i++)
    if (p.modn(primes[i]) === 0) {
      if (p.cmpn(primes[i]) === 0) {
        return true;
      } else {
        return false;
      }
    }

  return true;
}
function fermatTest(p) {
  const red = BN.mont(p);
  return TWO.toRed(red).redPow(p.sub(ONE)).fromRed().cmp(ONE) === 0;
}
const immediate = typeof setImmediate === 'function' ? setImmediate : setTimeout;
function nextTick () {
  return new Promise(function (done) {
    immediate(done);
  });
}
function * _getPrime(bits) {
  while (true) {
    const num = new BN(randomBytes(Math.ceil(bits / 8)));
    while (num.bitLength() > bits) {
       num.ishrn(1);
     }
     if (num.isEven()) {
       num.iadd(ONE);
     }
     if (!num.testn(1)) {
       num.iadd(TWO);
     }
     millerRabin = millerRabin || new MillerRabin();
     if (simpleSieve(num) && fermatTest(num) && millerRabin.test(num)) {
       return num;
     }
     yield nextTick();
   }
}
