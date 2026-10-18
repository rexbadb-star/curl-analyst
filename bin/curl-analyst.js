#!/usr/bin/env node
import { main } from '../src/cli.js';

const flush = (stream) => new Promise((resolve) => stream.write('', resolve));

main(process.argv.slice(2)).then(
  async (code) => {
    process.exitCode = code ?? 0;
    // Pastikan semua output terkirim ke pipe/file sebelum keluar, lalu paksa
    // exit — permintaan AI yang menggantung (setelah timeout) tidak boleh
    // menahan event loop.
    await flush(process.stdout);
    await flush(process.stderr);
    process.exit(process.exitCode);
  },
  async (err) => {
    console.error('Kesalahan:', err?.message ?? String(err));
    process.exitCode = 1;
    await flush(process.stdout);
    await flush(process.stderr);
    process.exit(1);
  },
);
