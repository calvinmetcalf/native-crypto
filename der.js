'use strict';
var assert = require('minimalistic-assert');

exports.fromDer = fromDer;
exports.toDER = toDER;

function toDER (input) {
  if (input.length % 2) {
    input = Buffer.concat([new Buffer([0]), input]);
  }
  var sliceLen = Math.floor(input.length / 2);
  var r = input.slice(0, sliceLen);
  var s = input.slice(sliceLen);

  // Pad values
  if (r[0] & 0x80) {
    r = Buffer.concat([new Buffer([0]), r]);
  }
  // Pad values
  if (s[0] & 0x80) {
    s = Buffer.concat([new Buffer([0]), s]);
  }
  r = rmPadding(r);
  s = rmPadding(s);

  var rarr = [0x02];
  constructLength(rarr, r.length);
  var sarr = [0x02];
  constructLength(sarr, s.length);
  var backHalf = Buffer.concat([new Buffer(rarr), r, new Buffer(sarr), s]);
  var head = [0x30];
  constructLength(head, backHalf.length);
  return Buffer.concat([new Buffer(head), backHalf]);
}
function constructLength(arr, len) {
  if (len < 0x80) {
    arr.push(len);
    return;
  }
  var octets = 1 + (Math.log(len) / Math.LN2 >>> 3);
  arr.push(octets | 0x80);
  while (octets) {
    if (octets-- === 1) {
      arr.push(len & 0xff);
      return;
    }
    arr.push((len >>> (octets << 3)) & 0xff);
  }
}

function rmPadding(buf) {
  var i = 0;
  var len = buf.length - 1;
  while (!buf[i] && !(buf[i + 1] & 0x80) && i < len) {
    i++;
  }
  if (i === 0) {
    return buf;
  }
  return buf.slice(i);
}

function fromDer(input, len) {
  var p = {};
  p.place = 0;
  assert.equal(input[p.place++], 0x30);
  getLength(input, p);
  assert.equal(input[p.place++], 0x02);
  var rlen = getLength(input, p);
  var r = input.slice(p.place, rlen + p.place);
  p.place += rlen;
  assert.equal(input[p.place++], 0x02);
  var slen = getLength(input, p);
  assert.equal(input.length, slen + p.place);
  var s = input.slice(p.place, slen + p.place);
  if (!r[0] && (r[1] & 0x80)) {
    r = r.slice(1);
  }
  if (!s[0] && (s[1] & 0x80)) {
    s = s.slice(1);
  }
  if (r.length < len) {
    let dif = new Buffer(len - r.length);
    dif.fill(0);
    r = Buffer.concat([dif, r]);
  }
  if (s.length < len) {
    let dif = new Buffer(len - s.length);
    dif.fill(0);
    s = Buffer.concat([dif, s]);
  }
  return Buffer.concat([r, s]);
}
function getLength(buf, p) {
  var initial = buf[p.place++];
  if (!(initial & 0x80)) {
    return initial;
  }
  var octetLen = initial & 0xf;
  var data = buf.readUIntBE(p.place, octetLen);
  p.place += octetLen;
  return data;
}
