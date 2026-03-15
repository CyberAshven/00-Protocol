// Stub for Node's https module - not needed in browser (axios uses XMLHttpRequest)
class Agent { constructor() {} }
module.exports = { Agent, request: () => {}, get: () => {} };
