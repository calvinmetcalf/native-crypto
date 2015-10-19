crypto-native
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
