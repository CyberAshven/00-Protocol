// Browser crypto stub - delegates to Web Crypto API
module.exports = {
  randomBytes: function(n) {
    const buf = new Uint8Array(n);
    crypto.getRandomValues(buf);
    return Buffer.from(buf);
  },
  createHash: function() { throw new Error('Use Web Crypto API'); },
  createHmac: function() { throw new Error('Use Web Crypto API'); },
};
