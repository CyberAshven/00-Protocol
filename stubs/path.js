// Minimal path stub for browser
function join() { return Array.from(arguments).join('/').replace(/\/+/g, '/'); }
function normalize(p) { return p; }
function dirname(p) { return p.split('/').slice(0, -1).join('/'); }
function basename(p) { return p.split('/').pop(); }
module.exports = { join, normalize, dirname, basename, sep: '/' };
module.exports.default = module.exports;
