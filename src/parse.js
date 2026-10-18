export const METRIC_KEYS = [
  'http_code',
  'remote_ip',
  'http_version',
  'url_effective',
  'content_type',
  'time_namelookup',
  'time_connect',
  'time_appconnect',
  'time_starttransfer',
  'time_total',
  'size_download',
  'speed_download',
  'ssl_verify_result',
  'num_redirects',
  'redirect_url',
];

export const METRIC_SENTINEL = '__CURL_ANALYST_END__';

const NUMERIC_METRICS = new Set([
  'http_code',
  'time_namelookup',
  'time_connect',
  'time_appconnect',
  'time_starttransfer',
  'time_total',
  'size_download',
  'speed_download',
  'ssl_verify_result',
  'num_redirects',
]);

/** Format -w untuk curl: satu metrik per baris, diakhiri sentinel. */
export function buildWriteOut() {
  return METRIC_KEYS.map((k) => `%{${k}}\n`).join('') + METRIC_SENTINEL + '\n';
}

export function parseMetrics(stdout) {
  if (!stdout) return null;
  const lines = stdout.split(/\r?\n/);
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (lines[lines.length - 1] !== METRIC_SENTINEL) return null;
  const idx = lines.length - 1 - METRIC_KEYS.length;
  if (idx < 0) return null;
  const values = lines.slice(idx, idx + METRIC_KEYS.length);
  const out = {};
  METRIC_KEYS.forEach((key, i) => {
    const v = values[i] ?? '';
    out[key] = NUMERIC_METRICS.has(key) ? Number(v) : v;
  });
  return out;
}

const STATUS_RE = /^HTTP\/(\d(?:\.\d)?)\s+(\d{3})(?:[ \t]+([^\r\n]*))?/;

/**
 * Pindai teks header (file -D, atau respons mentah dari curl -i) menjadi
 * blok-blok respons: 1xx, redirect, lalu respons final ikut tercatat.
 */
export function scanHeaderBlocks(raw) {
  const blocks = [];
  const re = /^HTTP\/(\d(?:\.\d)?)\s+(\d{3})(?:[ \t]+([^\r\n]*))?/gm;
  let m;
  while ((m = re.exec(raw))) {
    blocks.push({
      startIdx: m.index,
      httpVersion: m[1],
      code: Number(m[2]),
      statusText: (m[3] ?? '').trim(),
    });
  }
  for (let i = 0; i < blocks.length; i += 1) {
    const regionEnd = i + 1 < blocks.length ? blocks[i + 1].startIdx : raw.length;
    const region = raw.slice(blocks[i].startIdx, regionEnd);
    const blank = /\r?\n\r?\n/.exec(region);
    blocks[i].headerText = blank ? region.slice(0, blank.index) : region;
    blocks[i].bodyStart =
      i + 1 === blocks.length ? (blank ? blocks[i].startIdx + blank.index + blank[0].length : null) : null;
  }
  return blocks;
}

export function emptyHeaders() {
  return makeHeaders([], '', 0, '');
}

function makeHeaders(lines, httpVersion, code, statusText) {
  const map = new Map();
  const list = [];
  let prev = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && prev) {
      // baris lanjutan (header folding)
      const pair = list[list.length - 1];
      pair[1] = `${pair[1]} ${line.trim()}`;
      map.get(prev[0])[map.get(prev[0]).length - 1] = pair[1];
      continue;
    }
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    const key = name.toLowerCase();
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(value);
    list.push([name, value]);
    prev = [key, name];
  }
  return {
    httpVersion,
    code,
    statusText,
    list,
    get(name) {
      const v = map.get(String(name).toLowerCase());
      return v && v.length ? v[0] : null;
    },
    getAll(name) {
      return map.get(String(name).toLowerCase()) ?? [];
    },
    has(name) {
      return map.has(String(name).toLowerCase());
    },
  };
}

export function parseHeaderBlock(text) {
  const lines = String(text).split(/\r?\n/);
  const statusLine = lines.find((l) => STATUS_RE.test(l)) ?? '';
  const sm = STATUS_RE.exec(statusLine);
  const httpVersion = sm ? sm[1] : '1.1';
  const code = sm ? Number(sm[2]) : 0;
  const statusText = sm ? (sm[3] ?? '').trim() : '';
  const headerLines = lines.filter((l) => l !== statusLine && l.trim() !== '');
  return makeHeaders(headerLines, httpVersion, code, statusText);
}

/** Ambil semua blok respons yang sudah diparse dari teks header. */
export function parseHeaderBlocks(raw) {
  return scanHeaderBlocks(raw).map((b) => {
    const h = parseHeaderBlock(b.headerText);
    h.code = b.code;
    h.statusText = b.statusText;
    h.httpVersion = b.httpVersion;
    return h;
  });
}

/**
 * Parse respons mentah (mis. keluaran `curl -i`). Body diambil setelah blok
 * header terakhir; body respons antara redirect dilewati.
 */
export function parseRawResponse(raw) {
  const blocks = scanHeaderBlocks(raw);
  if (!blocks.length) return { headers: null, bodyText: String(raw ?? ''), code: 0 };
  const last = blocks[blocks.length - 1];
  const bodyText = last.bodyStart == null ? '' : raw.slice(last.bodyStart);
  return {
    blocks: blocks.map((b) => {
      const h = parseHeaderBlock(b.headerText);
      h.code = b.code;
      h.statusText = b.statusText;
      h.httpVersion = b.httpVersion;
      return h;
    }),
    headers: parseHeaderBlock(last.headerText),
    bodyText,
  };
}

/**
 * Kenali jenis body: JSON (valid/tidak), HTML, teks, kosong, biner.
 * Konten-Type dipakai sebagai petunjuk bila sniffing ambigu.
 */
export function sniffBody(text, contentType = '') {
  const ct = String(contentType ?? '');
  const ctJson = /json/i.test(ct);
  const t = String(text ?? '').replace(/^\uFEFF/, '').trimStart();
  if (!t) return ctJson ? { kind: 'json', valid: false, error: 'Body kosong' } : { kind: 'empty' };
  if (t.startsWith('{') || t.startsWith('[')) {
    try {
      return { kind: 'json', valid: true, data: JSON.parse(t) };
    } catch (e) {
      return { kind: 'json', valid: false, error: e.message };
    }
  }
  if (ctJson) return { kind: 'json', valid: false, error: 'Bukan objek/array JSON yang valid' };
  if (/^<!doctype\s+html|^<html[\s>]|<head[\s>]|<body[\s>]|<script[\s>]/i.test(t)) {
    return { kind: 'html' };
  }
  const bad = (t.match(/\uFFFD/g) ?? []).length;
  if (bad > t.length * 0.05) return { kind: 'binary' };
  if (/<\/?[a-z][^>]*>/i.test(t)) return { kind: 'html' };
  return { kind: 'text' };
}

export function parseSetCookie(raw) {
  const out = { name: null, attributes: {}, raw: raw };
  const parts = String(raw).split(';');
  const [n, ...rest] = parts[0].split('=');
  out.name = n.trim();
  for (const p of rest) void p; // nilai cookie tidak relevan untuk analisis
  for (const p of parts.slice(1)) {
    const idx = p.indexOf('=');
    const k = (idx === -1 ? p : p.slice(0, idx)).trim().toLowerCase();
    const v = idx === -1 ? true : p.slice(idx + 1).trim();
    if (k) out.attributes[k] = v;
  }
  return out;
}
