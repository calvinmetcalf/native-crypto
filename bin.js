// # for file in lib/*.js; do
// #   fname=$(basename $file)
// #   browserify-transform-cli inline-process-browser unreachable-branch-transform babelify < $file > browser/$fname
// # done
const fs = require('fs');
const path = require('path');
const inlineProcess = require('inline-process-browser');
const unreacable = require('unreachable-branch-transform');
const Babelify = require('babelify');

const dir = fs.readdirSync('./lib');

const babel = Babelify.configure({
  sourceMaps: false,
  sourceMapsAbsolute: false,
  presets: ['es2015']
})

for (let file of dir) {
  let inpath = path.join('lib', file);
  let outpath = path.join('browser', file);
  fs.createReadStream(inpath)
  .pipe(inlineProcess())
  .pipe(unreacable())
  .pipe(babel(file))
  .pipe(fs.createWriteStream(outpath));
}
