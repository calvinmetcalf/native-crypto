'use strict';

exports.encode = encode;
function encode(buf) {
  var str = buf.toString('base64');
  while (str[str.length - 1] === '=') {
    str = str.slice(0, -1);
  }
  return str.replace(/\+/g, '-').replace(/\//g, '_');
}
exports.decode = decode;
function decode(str) {
  str = str.replace(/\_/g, '/').replace(/\-/g, '+');
  switch (str.length % 4) {
    case 2:
      str += '=';
    // falls through
    case 3:
      str += '=';
  }
  return new Buffer(str, 'base64');
}