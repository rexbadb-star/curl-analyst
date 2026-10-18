import { readFile } from 'node:fs/promises';
import { runCurl } from './exec.js';
import { buildCtxFromRun, buildCtxFromRaw } from './ctx.js';
import { probeTls } from './tlsprobe.js';
import { runRules } from './rules/index.js';
import { buildReport, renderText, renderJson } from './report.js';
import { analyzeWithAi, DEFAULT_AI_MODEL } from './ai.js';

export const VERSION = '1.0.0';

const HELP = `curl-analyst ${VERSION} — analis cURL lokal (tanpa API, tanpa LLM)

Penggunaan:
  curl-analyst <url> [opsi]           Jalankan cURL, lalu analisis responsnya
  curl-analyst analyze [--file f]     Analisis output cURL yang sudah ada (stdin/--file)
                                      Contoh: curl -i https://situs.api/data | curl-analyst analyze

Opsi request:
  -X, --method METODE      Metode HTTP (default GET; otomatis POST bila -d dipakai)
  -H, --header 'K: V'      Tambah header (boleh diulang)
  -d, --data BODY          Body permintaan
  -L, --follow             Ikuti redirect (default: berhenti di 3xx)
  -k, --insecure           Abaikan verifikasi sertifikat TLS
  -t, --timeout DETIK      Timeout per request (default 30)

Opsi AI (opsional — DeepSeek via Puter, butuh internet & akun Puter gratis):
  --ai                     Sertakan analisis naratif AI bersama hasil aturan
  --ai-model MODEL         Model DeepSeek (default: ${DEFAULT_AI_MODEL})
  Auth: set PUTER_AUTH_TOKEN, atau jalankan sekali dari terminal interaktif
  (login browser, token disimpan di ~/.config/curl-analyst/puter-token).
  Tanpa --ai, tool tetap 100% offline dan tidak memuat paket AI.

Opsi keluaran:
  --json                   Hasil berupa JSON
  --strict                 Exit code 2 bila ada temuan KRITIS
  --no-color               Matikan warna ANSI
  --no-tls-probe           Lewati probe TLS terpisah (info sertifikat/protokol)
  --url URL                (mode analyze) URL asal untuk konteks & probe TLS
  -h, --help               Tampilkan bantuan
  -V, --version            Tampilkan versi`;

class UsageError extends Error {}

export function parseArgs(argv) {
  const a = {
    command: null,
    url: null,
    headers: [],
    data: null,
    method: null,
    methodExplicit: false,
    follow: false,
    insecure: false,
    timeout: 30,
    json: false,
    noColor: false,
    strict: false,
    noTlsProbe: false,
    ai: false,
    aiModel: DEFAULT_AI_MODEL,
    file: null,
    targetUrl: null,
    help: false,
    version: false,
  };
  const take = (i, flag) => {
    const v = argv[i + 1];
    if (v == null || v.startsWith('--')) throw new UsageError(`Flag ${flag} butuh nilai`);
    return v;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '-h': case '--help': a.help = true; break;
      case '-V': case '--version': a.version = true; break;
      case '-X': case '--method': a.method = take(i, arg).toUpperCase(); a.methodExplicit = true; i++; break;
      case '-H': case '--header': a.headers.push(take(i, arg)); i++; break;
      case '-d': case '--data': a.data = take(i, arg); i++; break;
      case '-L': case '--follow': a.follow = true; break;
      case '-k': case '--insecure': a.insecure = true; break;
      case '-t': case '--timeout': a.timeout = Number(take(i, arg)); i++; break;
      case '--json': a.json = true; break;
      case '--no-color': a.noColor = true; break;
      case '--strict': a.strict = true; break;
      case '--no-tls-probe': a.noTlsProbe = true; break;
      case '--ai': a.ai = true; break;
      case '--ai-model': a.aiModel = take(i, arg); i++; break;
      case '--file': a.file = take(i, arg); i++; break;
      case '--url': a.targetUrl = take(i, arg); i++; break;
      default:
        if (arg.startsWith('-')) throw new UsageError(`Opsi tidak dikenal: ${arg}`);
        if (arg === 'analyze' && !a.command) a.command = 'analyze';
        else if (!a.url) a.url = arg;
        else throw new UsageError(`Argumen berlebih: ${arg}`);
    }
  }
  if (!Number.isFinite(a.timeout) || a.timeout <= 0) throw new UsageError('--timeout harus angka detik > 0');
  return a;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function attachAi(report, args) {
  const ai = await analyzeWithAi(report, { model: args.aiModel });
  report.ai = ai;
  if (!ai.ok) process.stderr.write(`Catatan AI (opsional): gagal — ${ai.error}\n`);
}

function emit(report, args) {
  if (args.json) {
    process.stdout.write(`${renderJson(report)}\n`);
  } else {
    const color = !args.noColor && process.stdout.isTTY && !process.env.NO_COLOR;
    process.stdout.write(`${renderText(report, { color })}\n`);
  }
}

async function runFlow(args) {
  if (!args.url) throw new UsageError('URL tujuan belum diberikan. Contoh: curl-analyst https://example.com');
  let url = args.url;
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;

  const run = await runCurl(url, {
    method: args.method ?? 'GET',
    methodExplicit: args.methodExplicit,
    headers: args.headers,
    data: args.data,
    follow: args.follow,
    insecure: args.insecure,
    timeout: args.timeout,
  });

  let tls = null;
  let tlsProbed = false;
  if (!args.noTlsProbe && run.final?.url?.startsWith('https://')) {
    tls = await probeTls(run.final.url);
    tlsProbed = true;
  }

  const ctx = buildCtxFromRun(run, { tls, tlsProbed });
  ctx.follow = args.follow;
  ctx.insecure = args.insecure;

  if (!run.ok && run.error) {
    // request gagal total: tetap laporan, temuan status KRITIS sudah menangkap
    ctx.error = run.error;
  }
  const findings = runRules(ctx);
  const report = buildReport({ ctx, findings, version: VERSION });
  if (run.error) {
    report.requestError = { kind: run.error.kind, code: run.error.curlExit, message: run.error.message };
  }
  if (args.ai) await attachAi(report, args);
  emit(report, args);
  if (args.strict && report.counts.KRITIS > 0) return 2;
  return run.ok ? 0 : 1;
}

async function analyzeFlow(args) {
  let raw = '';
  if (args.file) {
    raw = await readFile(args.file, 'utf8');
  } else if (!process.stdin.isTTY) {
    raw = await readStdin();
  } else {
    throw new UsageError(
      'Tidak ada input. Tempel output cURL (curl -i …) lewat pipe, atau pakai --file, atau --help.',
    );
  }
  if (!raw.trim()) throw new UsageError('Input kosong — tidak ada output cURL untuk dianalisis.');

  let tls = null;
  let tlsProbed = false;
  if (!args.noTlsProbe && args.targetUrl?.startsWith('https://')) {
    tls = await probeTls(args.targetUrl);
    tlsProbed = true;
  }
  const ctx = buildCtxFromRaw(raw, { url: args.targetUrl, tls, tlsProbed, method: args.method ?? 'GET' });
  ctx.follow = args.follow;
  ctx.insecure = args.insecure;
  const findings = runRules(ctx);
  const report = buildReport({ ctx, findings, version: VERSION });
  if (args.ai) await attachAi(report, args);
  emit(report, args);
  if (args.strict && report.counts.KRITIS > 0) return 2;
  return 0;
}

export async function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`${e.message}\n\n${HELP}\n`);
      return 1;
    }
    throw e;
  }
  if (args.help) {
    process.stdout.write(`${HELP}\n`);
    return 0;
  }
  if (args.version) {
    process.stdout.write(`curl-analyst ${VERSION}\n`);
    return 0;
  }
  try {
    return args.command === 'analyze' ? await analyzeFlow(args) : await runFlow(args);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`${e.message}\n`);
      return 1;
    }
    if (e?.code === 'ECURLMISSING') {
      process.stderr.write(`${e.message}\n`);
      return 1;
    }
    throw e;
  }
}
