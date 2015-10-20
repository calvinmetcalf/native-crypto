'use strict';

module.exports = normalize;
var toNode = {
  'sha': 'SHA1',
  'sha-1': 'SHA1',
  'sha1': 'SHA1',
  'sha256': 'SHA256',
  'sha-256': 'SHA256',
  'sha384': 'SHA384',
  'sha-384': 'SHA384',
  'sha-512': 'SHA512',
  'sha512': 'SHA512',
  'p-256': 'prime256v1',
  'prime256v1': 'prime256v1',
  'secp256r1': 'prime256v1',
  'secp384r1': 'secp384r1',
  'p-384': 'secp384r1',
  'secp521r1': 'secp521r1',
  'p-521': 'secp521r1'
};
var toBrowser = {
  'sha': 'SHA-1',
  'sha-1': 'SHA-1',
  'sha1': 'SHA-1',
  'sha256': 'SHA-256',
  'sha-256': 'SHA-256',
  'sha384': 'SHA-384',
  'sha-384': 'SHA-384',
  'sha-512': 'SHA-512',
  'sha512': 'SHA-512',
  'p-256': 'P-256',
  'prime256v1': 'P-256',
  'secp256r1': 'P-256',
  'secp384r1': 'P-384',
  'p-384': 'P-384',
  'secp521r1': 'P-521',
  'p-521': 'P-521',
  'rs256': 'SHA-256',
  'rs384': 'SHA-384',
  'rs512': 'SHA-512'
};
function normalize(name, node) {
  var out;
  if (node) {
    out = toNode[name.toLowerCase()];
  } else {
    out = toBrowser[name.toLowerCase()];
  }
  if (out) {
    return out;
  }
  throw new Error(`unknown name: ${name}`);
}
