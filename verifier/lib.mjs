// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
// Loads the verifier core in Node, from the same bytes the page ships: the
// committed noble bundle and src/verify-core.js. Used by the command-line tool
// and by every test, so what is tested is what is shipped.
import { readFileSync, openSync, readSync, closeSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

export function load() {
  vm.runInThisContext(readFileSync(join(here, 'vendor', 'noble.iife.js'), 'utf8'));
  const core = require(join(here, 'src', 'verify-core.js'));
  return { V: core.create(globalThis.NobleNF), noble: globalThis.NobleNF };
}

// The slice of the File interface the core uses, over a path.
export function fileLike(path) {
  const size = statSync(path).size;
  return {
    size,
    slice(start, end) {
      return {
        async arrayBuffer() {
          const fd = openSync(path, 'r');
          try {
            const buf = Buffer.alloc(end - start);
            readSync(fd, buf, 0, end - start, start);
            return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);
          } finally { closeSync(fd); }
        },
      };
    },
  };
}
