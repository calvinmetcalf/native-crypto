'use strict';

module.exports = normalize;
var toNode = {
  'sha256': 'SHA256',
  'sha-256': 'SHA256',
  'sha384': 'SHA384',
  'sha-384': 'SHA384',
  'sha-512': 'SHA512',
  'sha512': 'SHA512'
};
var toBrowser = {
  'sha256': 'SHA-256',
  'sha-256': 'SHA-256',
  'sha384': 'SHA-384',
  'sha-384': 'SHA-384',
  'sha-512': 'SHA-512',
  'sha512': 'SHA-512'
}
function normalize(name, node) {
  if (node) {
    return toNode[name.toLowerCase()];
  }
  return toBrowser[name.toLowerCase()];
}
