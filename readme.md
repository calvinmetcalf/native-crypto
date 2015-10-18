crypto-native
===

The intent of this is browserifable crypt, which uses the node module on the server,
the subtle crypto api if available and the browserify-crypto if not.

Methods

Hash
===

```js
var hash = new Hash(algo);
hash.update(buffer).update(otherBuffer);
hash.digest().then(function (yourHash){});
```
Hmac
===

```js
var hmac = new Hmac(algo, keyAsBuffer);
hash.update(buffer).update(otherBuffer);
hash.digest().then(function (yourHmac) {});
// or
var hmac = new Hmac(algo, keyAsBuffer, otherHmacToVerify);
hash.update(buffer).update(otherBuffer);
hash.verify().then(function (result) {
  // result is a boolean
});
```
