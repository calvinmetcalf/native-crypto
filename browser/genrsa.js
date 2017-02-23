'use strict';

var rsaKeygen = false;
var BN = require('bn.js');
var debug = require('debug')('native-crypto:gen-rsa');
var base64url = require('./base64url');
var randomBytes = require('randombytes');
var ONE = new BN(1);
var TWO = new BN(2);
var MillerRabin = require('miller-rabin');
var parseRSA = require('./parseRSA');
var millerRabin = void 0;
module.exports = genRSA;
function genRSA(len, exponent) {
  if (!true) {
    return genRSAnode(len, exponent).catch(function (e) {
      debug('unable to generate key nativly due to ' + e);
      return genRSAjs(len, exponent);
    });
  }
  return genRSAjs(len, exponent);
}
function genRSAnode(len, exponent) {
  return new Promise(function (yes) {
    var exponentNum = parseInt(exponent.toString('hex'), 16);
    var key = rsaKeygen.generate(len, exponentNum);
    debug('generated rsa key nativly');
    yes(parseRSA({
      publicKey: key.public_key,
      privateKey: key.private_key
    }));
  });
}
function genRSAjs(len, exponent) {
  var e = new BN(exponent);
  var qlen = len >> 1;
  var plen = len - qlen;
  return Promise.all([getPrime(qlen), getPrime(plen)]).then(function (primes) {
    var q = primes[0];
    var p = primes[1];
    return checkPrimes(q, p);
  }).then(after);
  function checkPrimes(q, p) {
    var pcmpq = p.cmp(q);
    if (pcmpq === 0) {
      return getPrime(plen).then(function (newp) {
        return checkPrimes(q, newp);
      });
    }
    if (pcmpq < 0) {
      var tmp = p;
      p = q;
      q = tmp;
    }
    var pmin = p.sub(ONE);
    if (!ensureCoprime(pmin, e)) {
      return getPrime(plen).then(function (newp) {
        return checkPrimes(q, newp);
      });
    }
    var qmin = q.sub(ONE);
    if (!ensureCoprime(qmin, e)) {
      return getPrime(qlen).then(function (newq) {
        return checkPrimes(newq, p);
      });
    }
    var n = p.mul(q);
    var phi = n.sub(q);
    phi.isub(p);
    phi.iadd(ONE);
    if (!ensureCoprime(phi, e)) {
      return Promise.all([getPrime(qlen), getPrime(plen)]).then(function (primes) {
        var q = primes[0];
        var p = primes[1];
        return checkPrimes(q, p);
      });
    }
    if (n.bitLength() !== len) {
      return getPrime(qlen).then(function (newq) {
        return checkPrimes(newq, p);
      });
    }
    return { p: p, q: q, phi: phi, n: n, pmin: pmin, qmin: qmin };
  }
  function after(opts) {
    var p = opts.p;
    var q = opts.q;
    var phi = opts.phi;
    var n = opts.n;
    var pmin = opts.pmin;
    var qmin = opts.qmin;
    var d = e.invm(phi);
    var dp = d.mod(pmin);
    var dq = d.mod(qmin);
    var qi = q.invm(p);
    var encodedN = base64url.encode(new Buffer(n.toArray()));
    var encodedE = base64url.encode(new Buffer(e.toArray()));
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
  if (primes !== null) return primes;

  var limit = 0x100000;
  var res = [];
  res[0] = 2;
  var j = void 0;
  for (var i = 1, k = 3; k < limit; k += 2) {
    var sqrt = Math.ceil(Math.sqrt(k));
    for (j = 0; j < i && res[j] <= sqrt; j++) {
      if (k % res[j] === 0) break;
    }if (i !== j && res[j] <= sqrt) continue;
    res[i++] = k;
  }
  primes = res;
  return res;
}

function simpleSieve(p) {
  var primes = _getPrimes();

  for (var i = 0; i < primes.length; i++) {
    if (p.modn(primes[i]) === 0) {
      if (p.cmpn(primes[i]) === 0) {
        return true;
      } else {
        return false;
      }
    }
  }return true;
}
function fermatTest(p) {
  var red = BN.mont(p);
  return TWO.toRed(red).redPow(p.sub(ONE)).fromRed().cmp(ONE) === 0;
}
var immediate = typeof setImmediate === 'function' ? setImmediate : setTimeout;
function nextTick() {
  return new Promise(function (done) {
    immediate(done);
  });
}
var prevPrimes = new Set();
function getPrime(bits, times) {
  if (times === undefined || times === -1) {
    times = 20;
  }
  var num = new BN(randomBytes(Math.ceil(bits / 8)));
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
  var stringRep = num.toString();
  if (prevPrimes.has(stringRep)) {
    if (!times) {
      return nextTick(times).then(function () {
        return getPrime(bits);
      });
    }
    return getPrime(bits, times - 1);
  }
  prevPrimes.add(stringRep);
  if (simpleSieve(num) && fermatTest(num) && millerRabin.test(num)) {
    return Promise.resolve(num);
  }
  if (!times) {
    return nextTick(times).then(function () {
      return getPrime(bits);
    });
  }
  return getPrime(bits, times - 1);
}