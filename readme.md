native-crypto
===

The intent of this is browserifable crypt, which uses the node module on the server, the subtle crypto api if available and the browserify-crypto if not.

Methods

Hash
===
var nCrypto - require('native-crypto');
```js
var hash = new nCrypto.Hash(algo);
hash.update(buffer).update(otherBuffer);
hash.digest().then(function (yourHash){});
```
Hmac
===

```js
var hmac = new nCrypto.Hmac(algo, keyAsBuffer);
hash.update(buffer).update(otherBuffer);
hash.digest().then(function (yourHmac) {});
// or
var hmac = new nCrypto.Hmac(algo, keyAsBuffer, otherHmacToVerify);
hash.update(buffer).update(otherBuffer);
hash.verify().then(function (result) {
  // result is a boolean
});
```

encrypt/decrypt
===

```js
nCrypto.encrypt(key, iv, plainText, aad).then(function (cipherText) {
  return nCrypto.decrypt(key, iv, cipherText, aad);
}).then(function (res) {
  // res and plainText should be the same
});
// aad is optional
nCrypto.encrypt(key, iv, plainText).then(function (cipherText) {
  return nCrypto.decrypt(key, iv, cipherText);
}).then(function (res) {
  // res and plainText should be the same
});
```

Signatures
===

Only JWK are supported and both RSA or ECDSA keys are supported (DSA is not
supported by web crypto).  If using RSA make sure the `.alg` parameter is set on the key and is one of `RS256`, `RS384`, or `RS512` (based on what hash function you want to be using).

```js
var sign = new nCrypto.Signature(privateKey);
sign.update(buffer).update(otherBuffer);
sign.sign().then(function (yourSig) {});
// or
var verify = new nCrypto.Signature(privateKey, sigToVerify);
verify.update(buffer).verify(otherBuffer);
verify.verify().then(function (result) {
  // result is a boolean
});
```

PBKDF2
===

No parameters are optional key may be a string or buffer, salt must be buffers, length is in bytes,
algo may be any of the supported hash algorithms.

```js
nCrypto.pbkdf2(key, salt, iterations, length, algo).then(function (derivedKey) {
  // you have it
});
```

RSA
===

For RSA encryption and decryption, only OAEP padding is supported and only using a public key to encrypt and private to decrypt.

```js
nCrypto.rsa.encrypt(key, data).then(function (result) {
  // result is a buffer
});
nCrypto.rsa.encrypt(key, encryptedData).then(function (result) {
  // result is a buffer
});
```

Key Generation
===

You can generate key pairs for signing/verifying in either RSA or ECDSA, or use with ECDH.

Accepts either a ECC curve:

```js
nCrypto.generate('P-256').then(function (keypair) {
  // keypair.publicKey and keypair.privateKey are JWK
});
nCrypto.generate('P-384').then(...
nCrypto.generate('P-521').then(...
```

or an RSA algorithm identifier and optional length and exponent (as buffer)

```js
nCrypto.generate('RS256').then(...
nCrypto.generate('RS512', 4096, 65537).then(...
nCrypto.generate('RS384', 2048, 3).then(...
```

key length defaults to 4096 and public exponent to 65537 (aka `0x10001`)


ECDH
===

Generate an ECDH Object, accepts a curve type and optionally a private key.

```js
var ecdh1 = new nCrypto.ECDH('P-256'); // generates a new key
var ecdh2 = new nCrypto.ECDH('P-256', keypair.privateKey);
// you can pass in the privateKey from a generate command
```

You can use `.getPublic()` and `.getPrivate()` to get the public and private keys of the pair, this is especially handy if you had it generate the key for you, both return a promise.

```js
ecdh1.getPublic().then(function (publicKey) {
  // do stuff
});
```

Finally you can generate a shared secret with the `.computeSecret` method, which takes a public key as a method.

```js
ecdh2.computeSecret(publicKey).then(function (secret) {
  // do stuff
})
```
