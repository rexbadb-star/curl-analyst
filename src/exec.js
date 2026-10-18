import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { buildWriteOut, parseMetrics, parseHeaderBlocks, emptyHeaders } from './parse.js';

const pExecFile = promisify(execFile);

export const DEFAULT_ACCEPT_ENCODING = 'gzip, deflate, br';
const MAX_HOPS = 10;
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

/** Decode body sesuai Content-Encoding respons. Gagal decode = pakai apa adanya. */
export function decodeBody(buf, contentEncoding) {
  const enc = String(contentEncoding ?? '').toLowerCase().trim();
  if (!enc || enc === 'identity') return { buffer: buf, decoded: false, failed: null };
  try {
    if (enc === 'gzip' || enc === 'x-gzip') return { buffer: zlib.gunzipSync(buf), decoded: true, failed: null };
    if (enc === 'br') return { buffer: zlib.brotliDecompressSync(buf), decoded: true, failed: null };
    if (enc === 'deflate') {
      try {
        return { buffer: zlib.inflateSync(buf), decoded: true, failed: null };
      } catch {
        return { buffer: zlib.inflateRawSync(buf), decoded: true, failed: null };
      }
    }
    if (enc === 'zstd' && typeof zlib.zstdDecompressSync === 'function') {
      return { buffer: zlib.zstdDecompressSync(buf), decoded: true, failed: null };
    }
    return { buffer: buf, decoded: false, failed: `encoding tidak didukung: ${enc}` };
  } catch (e) {
    return { buffer: buf, decoded: false, failed: `gagal decode ${enc}: ${e.message}` };
  }
}

function classifyCurlError(code, stderr) {
  const s = String(stderr ?? '');
  const map = {
    3: ['url', 'URL malformed'],
    6: ['dns', 'Resolusi hostname gagal'],
    7: ['connect', 'Gagal terhubung ke server'],
    18: ['partial', 'Transfer terpotong'],
    28: ['timeout', 'Timeout tercapai'],
    35: ['ssl', 'TLS/SSL handshake gagal'],
    51: ['ssl', 'Sertifikat TLS tidak dapat diverifikasi'],
    52: ['ssl', 'Server tidak merespons (kemungkinan TLS gagal)'],
    53: ['ssl', 'Sertifikat CA tidak ditemukan'],
    54: ['ssl', 'Sertifikat TLS gagal rotasi'],
    56: ['connect', 'Penerimaan data gagal'],
    58: ['ssl', 'Server sertifikat bermasalah'],
    60: ['ssl', 'Sertifikat TLS tidak valid'],
    64: ['ssl', 'Sertifikat TLS tidak valid'],
    77: ['ssl', 'File CA bermasalah'],
    92: ['ssl', 'TLS handshake terputus (HTTP/2)'],
  };
  const known = map[code];
  const message = s.split(/\r?\n/).filter(Boolean).pop() ?? `curl exit ${code}`;
  return { kind: known ? known[0] : 'other', message: known ? known[1] : message, stderr: s.trim() };
}

function buildArgs({ url, method, methodExplicit, data, headers, insecure, timeout }) {
  const args = ['-sS', '--max-time', String(timeout), '-w', buildWriteOut()];
  if (insecure) args.push('-k');
  const allHeaders = [...headers];
  if (!allHeaders.some((h) => /^accept-encoding:/i.test(h))) {
    allHeaders.push(`Accept-Encoding: ${DEFAULT_ACCEPT_ENCODING}`);
  }
  for (const h of allHeaders) args.push('-H', h);
  if (data != null) args.push('--data-binary', String(data));
  if (methodExplicit && method) args.push('-X', method);
  args.push(url);
  return args;
}

async function curlOnce(opts) {
  const dir = opts.tmpDir;
  const hdrPath = path.join(dir, `hdr${opts.index}.txt`);
  const bodyPath = path.join(dir, `body${opts.index}.bin`);
  const args = buildArgs({ ...opts, url: opts.targetUrl, method: opts.method });
  args.splice(args.indexOf('-w'), 0, '-D', hdrPath, '-o', bodyPath);

  let stdout = '';
  let stderr = '';
  let exitCode = 0;
  try {
    const r = await pExecFile('curl', args, { maxBuffer: 16 * 1024 * 1024, windowsHide: true });
    stdout = r.stdout ?? '';
    stderr = r.stderr ?? '';
  } catch (e) {
    if (e.code === 'ENOENT') {
      const err = new Error('Binary `curl` tidak ditemukan di PATH. Install curl terlebih dahulu.');
      err.code = 'ECURLMISSING';
      throw err;
    }
    exitCode = typeof e.code === 'number' ? e.code : 1;
    stdout = e.stdout ?? '';
    stderr = e.stderr ?? '';
  }
  const headerRaw = await readFile(hdrPath, 'utf8').catch(() => '');
  const bodyRaw = await readFile(bodyPath).catch(() => Buffer.alloc(0));
  const metrics = parseMetrics(stdout);
  const blocks = parseHeaderBlocks(headerRaw);
  const headers = blocks.length ? blocks[blocks.length - 1] : emptyHeaders();
  if (metrics && !headers.code) headers.code = metrics.http_code ?? 0;
  return { headerRaw, bodyRaw, metrics, blocks, headers, stdout, stderr, exitCode };
}

/**
 * Jalankan curl (manual redirect bila --follow) dan kumpulkan header,
 * body terdekompresi, dan metrik tiap hop.
 */
export async function runCurl(url, options = {}) {
  const opts = {
    method: 'GET',
    methodExplicit: false,
    headers: [],
    data: null,
    follow: false,
    insecure: false,
    timeout: 30,
    ...options,
  };
  const tmpDir = await mkdtemp(path.join(tmpdir(), 'curl-analyst-'));
  const hops = [];
  try {
    let currentUrl = url;
    let currentMethod = opts.method;
    let currentData = opts.data;
    let lastStderr = '';
    let requestError = null;

    for (let i = 0; i < MAX_HOPS; i += 1) {
      const res = await curlOnce({
        tmpDir,
        index: i,
        targetUrl: currentUrl,
        method: currentMethod,
        methodExplicit: opts.methodExplicit,
        data: opts.data,
        headers: opts.headers,
        insecure: opts.insecure,
        timeout: opts.timeout,
      });
      lastStderr = res.stderr;
      const hop = {
        index: i,
        url: currentUrl,
        method: currentMethod,
        status: res.headers.code || res.metrics?.http_code || 0,
        statusText: res.headers.statusText,
        httpVersion: res.metrics?.http_version || res.headers.httpVersion || '1.1',
        headers: res.headers,
        blocks: res.blocks,
        metrics: res.metrics,
        bodyBuffer: res.bodyRaw,
        stderr: res.stderr,
      };
      hops.push(hop);

      if (res.exitCode !== 0) {
        requestError = { curlExit: res.exitCode, ...classifyCurlError(res.exitCode, res.stderr) };
        break;
      }

      const location = hop.status >= 300 && hop.status < 400 ? hop.headers.get('location') : null;
      if (!opts.follow || !location || !REDIRECT_CODES.has(hop.status)) break;

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        hop.badLocation = location;
        break;
      }
      hop.redirectTo = nextUrl;
      // perilaku curl: POST tanpa -X dipaksa jadi GET pada 301/302/303
      if (!opts.methodExplicit && [301, 302, 303].includes(hop.status) && currentData != null) {
        currentMethod = 'GET';
        currentData = null;
      }
      currentUrl = nextUrl;
    }

    return {
      ok: !requestError,
      error: requestError,
      hops,
      final: hops[hops.length - 1] ?? null,
      stderr: lastStderr,
      requestedUrl: url,
    };
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
