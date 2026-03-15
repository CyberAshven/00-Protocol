const esbuild = require('esbuild');
const fs = require('fs');

esbuild.build({
  entryPoints: ['monero-browser-wrapper.js'],
  bundle: true,
  outfile: 'landing/lib/monero-ts.js',
  format: 'esm',
  platform: 'browser',
  target: 'es2020',
  define: {
    'process.env.NODE_ENV': '"production"',
    'process.env.NODE_DEBUG': '""',
    'process.version': '"v20.0.0"',
    'process.platform': '"browser"',
    'process.stderr': 'false',
    'global': 'globalThis',
  },
  // Stub out Node modules not needed in browser
  alias: {
    'http': './stubs/http.js',
    'https': './stubs/https.js',
    'net': './stubs/empty.js',
    'tls': './stubs/empty.js',
    'fs': './stubs/empty.js',
    'child_process': './stubs/empty.js',
    'assert': './stubs/assert.js',
    'path': './stubs/path.js',
    'crypto': './stubs/crypto.js',
    'stream': './stubs/empty.js',
    'zlib': './stubs/empty.js',
    'url': './stubs/empty.js',
    'util': './stubs/empty.js',
    'os': './stubs/empty.js',
    'worker_threads': './stubs/empty.js',
  },
  external: [],
  minify: true,
  sourcemap: false,
}).then(() => {
  console.log('Built landing/lib/monero-ts.js');

  // Copy worker file
  fs.mkdirSync('landing/lib', { recursive: true });
  fs.copyFileSync('node_modules/monero-ts/dist/monero.worker.js', 'landing/lib/monero.worker.js');
  console.log('Copied monero.worker.js');
}).catch(err => {
  console.error(err);
  process.exit(1);
});
