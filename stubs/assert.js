// Browser-compatible assert stub
function assert(val, msg) {
  if (!val) throw new Error(msg || 'Assertion failed');
}
assert.equal = function(a, b, msg) { if (a !== b) throw new Error(msg || `${a} !== ${b}`); };
assert.notEqual = function(a, b, msg) { if (a === b) throw new Error(msg || `${a} === ${b}`); };
assert.deepEqual = assert.equal;
assert.strictEqual = assert.equal;
assert.ok = assert;
module.exports = assert;
module.exports.default = assert;
