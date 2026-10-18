import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { exec } from 'node:child_process';

export const DEFAULT_AI_MODEL = 'deepseek/deepseek-v4.1-flash';
const AUTH_TIMEOUT_MS = 120_000;
const CHAT_TIMEOUT_MS = 90_000;

/** Direktori konfigurasi (token cache). Bisa dioverride untuk test/CI. */
function configDir() {
  return process.env.CURL_ANALYST_CONFIG_DIR || path.join(os.homedir(), '.config', 'curl-analyst');
}
function tokenFile() {
  return path.join(configDir(), 'puter-token');
}

function readCachedToken() {
  try {
    const t = fs.readFileSync(tokenFile(), 'utf8').trim();
    return t || null;
  } catch {
    return null;
  }
}

function cacheToken(token) {
  try {
    fs.mkdirSync(configDir(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(tokenFile(), `${token}\n`, { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

function openBrowser(url) {
  let cmd;
  let args;
  if (process.platform === 'win32') {
    cmd = 'cmd';
    args = ['/c', 'start', '', url];
  } else if (process.platform === 'darwin') {
    cmd = 'open';
    args = [url];
  } else {
    cmd = 'xdg-open';
    args = [url];
  }
  exec(cmd, args, () => {}); // abaikan gagal buka browser — user masih bisa buka URL manual
}

/**
 * Login via browser: buka puter.com, jalankan server callback lokal, tunggu token.
 * Menutup server & timer di kedua jalur agar tidak bocor handle.
 */
function browserAuth({ timeoutMs = AUTH_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err, token) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      server.close();
      if (err) reject(err);
      else resolve(token);
    };
    const timer = setTimeout(
      () => finish(new Error('Login browser kedaluwarsa (timeout 2 menit)')),
      timeoutMs,
    );
    const server = http.createServer((req, res) => {
      let token = null;
      try {
        token = new URL(req.url, 'http://localhost/').searchParams.get('token');
      } catch {
        /* abaikan */
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(
        token
          ? '<!doctype html><meta charset="utf-8"><title>Login berhasil</title><h1>Login berhasil</h1><p>Silakan kembali ke terminal.</p>'
          : '<!doctype html><meta charset="utf-8"><title>Tanpa token</title><p>Parameter token tidak ditemukan. Coba lagi.</p>',
      );
      if (token) finish(null, token);
      // bila tanpa token: biarkan terbuka, user bisa retry dari browser
    });
    server.on('error', (e) => finish(e));
    server.listen(0, '127.0.0.1', function onListen() {
      const redirect = `http://localhost:${this.address().port}`;
      const url = `https://puter.com/?action=authme&redirectURL=${encodeURIComponent(redirect)}`;
      openBrowser(url);
    });
  });
}

/**
 * Urutan resolusi token: env PUTER_AUTH_TOKEN → cache lokal → login browser
 * (browser hanya bila konteks interaktif / diminta eksplisit).
 */
export async function resolveAuthToken({
  allowBrowserAuth = Boolean(process.stderr.isTTY),
  timeoutMs,
} = {}) {
  const envToken = process.env.PUTER_AUTH_TOKEN?.trim();
  if (envToken) return { token: envToken, source: 'env' };
  const cached = readCachedToken();
  if (cached) return { token: cached, source: 'cache' };
  if (!allowBrowserAuth) {
    throw new Error(
      'Token Puter belum ada. Set PUTER_AUTH_TOKEN, atau jalankan sekali dari terminal interaktif untuk login browser.',
    );
  }
  const token = await browserAuth({ timeoutMs });
  if (!token) throw new Error('Login browser tidak menghasilkan token.');
  cacheToken(token);
  return { token, source: 'browser' };
}

/** Muat SDK puter.js secara dinamis — hanya saat --ai dipakai. */
async function loadPuter(token) {
  let mod;
  try {
    mod = await import('@heyputer/puter.js/src/init.cjs');
  } catch (e) {
    throw new Error(`Paket @heyputer/puter.js belum terpasang — jalankan \"npm install\" dulu. (${e.message})`);
  }
  const init = mod.init ?? mod.default?.init;
  if (typeof init !== 'function') throw new Error('API @heyputer/puter.js tidak dikenal (init tidak ditemukan).');
  return init(token);
}

const REDACT = /((?:set-cookie|cookie|authorization|proxy-authorization|x-api-key|api-key)\s*[:=])[^\n;]*/gi;

function safe(str, max = 200) {
  if (str == null) return undefined;
  const s = String(str).replace(REDACT, '$1 [diredaksi]');
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/**
 * Susun prompt analisis dari laporan. Hanya metadata & temuan yang dikirim;
 * cookie/token tidak ikut (sudah diredaksi & tidak pernah disertakan utuh).
 */
export function buildAiPrompt(report) {
  const nonOk = report.findings.filter((f) => f.severity !== 'OK').slice(0, 40);
  const payload = {
    url: report.request.url,
    metode: report.request.method,
    ikhtisar: {
      skor: report.score,
      grade: report.grade,
      hitungan: report.counts,
      status: report.response.status,
      statusText: report.response.statusText,
      httpVersion: report.response.httpVersion,
      contentType: report.response.contentType,
      kompresi: report.response.contentEncoding,
      ukuranBody: report.response.sizeBytes,
      waktuTotalDetik: report.response.timeTotalSec,
      ttfbDetik: report.response.timeTtfbSec,
      redirect: report.response.redirects,
    },
    tls: report.tls ?? null,
    temuan: nonOk.map((f) => ({
      severity: f.severity,
      kategori: f.category,
      masalah: f.title,
      bukti: safe(f.evidence),
      saran: safe(f.suggestion),
    })),
  };
  return [
    'Kamu adalah analis performa & keamanan web senior. Berikut data respons HTTP hasil pemeriksaan otomatis curl-analyst (engine aturan lokal).',
    '',
    'Tulis analisis dalam Bahasa Indonesia dengan format persis:',
    '## Ringkasan',
    '2-4 kalimat gambaran besar kondisi respons ini.',
    '## Prioritas perbaikan',
    '3-5 poin bernomor: apa yang paling penting diperbaiki duluan dan kenapa berisikonya — elaborasi praktis, jangan menyalin teks saran secara verbatim.',
    '## Insight',
    '2-4 poin singkat: interaksi antar temuan, risiko kontekstual, atau hal yang perlu diperiksa manual.',
    '',
    'Aturan: gunakan HANYA data di bawah (jangan mengarang); jangan ulangi daftar temuan satu per satu; total maksimal ±300 kata.',
    '',
    'DATA:',
    JSON.stringify(payload),
  ].join('\n');
}

function normalizeContent(raw) {
  const c = raw?.message?.content ?? raw?.content ?? raw;
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) {
    return c
      .map((p) => (typeof p === 'string' ? p : (p?.text ?? p?.content ?? '')))
      .map((s) => String(s).trim())
      .filter(Boolean)
      .join('\n');
  }
  if (c == null) return '';
  return String(c);
}

function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} melebihi batas waktu ${Math.round(ms / 1000)} detik`)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function cleanError(e) {
  const msg = e?.message ?? String(e);
  if (/401|403|unauthorized|invalid token/i.test(msg)) {
    return `${msg} — token mungkin kedaluwarsa; hapus ${tokenFile()} atau set ulang PUTER_AUTH_TOKEN.`;
  }
  return msg;
}

/**
 * Analisis AI opsional: selalu mengembalikan { ok, model, ... } — tidak pernah
 * melempar — agar laporan aturan tetap terpakai walau AI gagal.
 *
 * @param {object} report laporan dari buildReport
 * @param {object} [opts]
 * @param {string} [opts.model]
 * @param {(prompt: string, opts: object) => Promise<any>} [opts.chat] fungsi chat (untuk test)
 * @param {string} [opts.token] token eksplisit (lewati resolusi)
 * @param {boolean} [opts.allowBrowserAuth]
 * @param {number} [opts.timeoutMs]
 */
export async function analyzeWithAi(report, opts = {}) {
  const { model = DEFAULT_AI_MODEL, chat, timeoutMs = CHAT_TIMEOUT_MS } = opts;
  try {
    let chatFn = chat;
    if (!chatFn) {
      const auth = opts.token
        ? { token: opts.token, source: 'explicit' }
        : await resolveAuthToken({ allowBrowserAuth: opts.allowBrowserAuth });
      const puter = await loadPuter(auth.token);
      chatFn = (prompt, o) => puter.ai.chat(prompt, o);
    }
    const prompt = buildAiPrompt(report);
    const raw = await withTimeout(chatFn(prompt, { model }), timeoutMs, 'AI');
    const narrative = normalizeContent(raw);
    if (!narrative.trim()) throw new Error('Respons AI kosong.');
    return { ok: true, model, narrative };
  } catch (e) {
    return { ok: false, model, error: cleanError(e) };
  }
}
