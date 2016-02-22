'use strict';
let rsaKeygen = false;;
if (!process.browser) {
  rsaKeygen = (function () {
    try {
      return require('rsa' + '-keygen');
    } catch(e) {}
  }());
}
const BN = require('bn.js');
const debug = require('debug')('native-crypto:gen-rsa');
const base64url = require('./base64url');
const randomBytes = require('randombytes');
const ONE = new BN(1);
const TWO = new BN(2);
const MillerRabin = require('miller-rabin');
const parseRSA = require('./parseRSA');
let millerRabin;
module.exports = genRSA;
function genRSA(len, exponent) {
  if (!process.browser && rsaKeygen !== false) {
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
function genRSAjs(len, exponent) {
  const e = new BN(exponent);
  const qlen = len >> 1;
  const plen = len - qlen;
  return Promise.all([getPrime(qlen), getPrime(plen)]).then(function (primes) {
    let q = primes[0];
    let p = primes[1];
    return checkPrimes(q, p);
  }).then(after);
  function checkPrimes(q, p) {
    let pcmpq = p.cmp(q);
    if (pcmpq === 0) {
      return getPrime(plen).then(function (newp) {
        return checkPrimes(q, newp);
      });
    }
    if (pcmpq < 0) {
      let tmp = p;
      p = q;
      q = tmp;
    }
    let pmin = p.sub(ONE);
    if (!ensureCoprime(pmin, e)) {
      return getPrime(plen).then(function (newp) {
        return checkPrimes(q, newp);
      });
    }
    let qmin = q.sub(ONE);
    if (!ensureCoprime(qmin, e)) {
      return getPrime(qlen).then(function (newq) {
        return checkPrimes(newq, p);
      });
    }
    let n = p.mul(q);
    let phi = n.sub(q);
    phi.isub(p);
    phi.iadd(ONE);
    if (!ensureCoprime(phi, e)) {
      return Promise.all([getPrime(qlen), getPrime(plen)]).then(function (primes) {
        let q = primes[0];
        let p = primes[1];
        return checkPrimes(q, p);
      });
    }
    if (n.bitLength() !== len) {
      return getPrime(qlen).then(function (newq) {
        return checkPrimes(newq, p);
      });
    }
    return {p,q,phi,n, pmin, qmin};
  }
  function after(opts) {
    let p = opts.p;
    let q = opts.q;
    let phi = opts.phi;
    let n = opts.n;
    let pmin = opts.pmin;
    let qmin = opts.qmin;
    const d = e.invm(phi);
    const dp = d.mod(pmin);
    const dq = d.mod(qmin);
    const qi = q.invm(p);
    const encodedN = base64url.encode(new Buffer(n.toArray()));
    const encodedE = base64url.encode(new Buffer(e.toArray()));
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
        d: base64url.encode(new Buffer(d.toArray())),
        p: base64url.encode(new Buffer(p.toArray())),
        q: base64url.encode(new Buffer(q.toArray())),
        dp: base64url.encode(new Buffer(dp.toArray())),
        dq: base64url.encode(new Buffer(dq.toArray())),
        qi: base64url.encode(new Buffer(qi.toArray())),
        key_ops: ['sign'],
        ext: true
      }
    };
  }
}
function ensureCoprime(pq, e) {
  return pq.gcd(e).cmp(ONE) === 0;
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
let prevPrimes = new Set();
function getPrime(bits, times) {
  if (times === undefined || times === -1) {
    times = 20;
  }
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
  const stringRep = num.toString();
  if (prevPrimes.has(stringRep)) {
    if (!times) {
      return nextTick(times).then(()=>getPrime(bits));
    }
    return getPrime(bits, times - 1);
  }
  prevPrimes.add(stringRep);
  if (simpleSieve(num) && fermatTest(num) && millerRabin.test(num)) {
    return Promise.resolve(num);
  }
  if (!times) {
    return nextTick(times).then(()=>getPrime(bits));
  }
  return getPrime(bits, times - 1);
}
