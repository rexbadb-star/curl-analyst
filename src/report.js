import { fmtBytes, fmtSeconds, truncate } from './util.js';

const DEDUCTION = { KRITIS: 20, PERINGATAN: 7, INFO: 1, OK: 0 };

export function scoreFindings(findings) {
  const counts = { KRITIS: 0, PERINGATAN: 0, INFO: 0, OK: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  let score = 100;
  for (const sev of ['KRITIS', 'PERINGATAN', 'INFO']) score -= counts[sev] * DEDUCTION[sev];
  score = Math.max(0, Math.min(100, score));
  const grade =
    score >= 90 ? 'SEHAT' : score >= 75 ? 'BAIK' : score >= 55 ? 'PERLU PERHATIAN' : 'BERMASALAH';
  return { score, grade, counts };
}

/**
 * Ringkasan narasi ala analis: paragraf yang menyusun gambaran besar dari
 * temuan (skor, jumlah, masalah teratas, kondisi teknis).
 */
export function buildSummary({ ctx, findings, stats }) {
  const { score, grade, counts } = stats;
  const totalChecks = findings.length;
  const p1 =
    `Respons ${ctx.url} dinilai ${score}/100 (${grade}). Dari ${totalChecks} pemeriksaan, ` +
    `ditemukan ${counts.KRITIS} kritikal, ${counts.PERINGATAN} peringatan, ${counts.INFO} info, ` +
    `dan ${counts.OK} yang lolos.`;

  const top = findings.filter((f) => f.severity === 'KRITIS' || f.severity === 'PERINGATAN').slice(0, 3);
  let p2;
  if (top.length) {
    p2 =
      'Masalah teratas: ' +
      top.map((f, i) => `(${i + 1}) ${f.title}${f.suggestion ? ` — ${f.suggestion}` : ''}`).join('; ') +
      '.';
  } else {
    p2 = 'Tidak ada temuan kritikal maupun peringatan pada pemeriksaan utama — kondisi respons tergolong baik.';
  }

  const status = ctx.final?.status ?? 0;
  const m = ctx.metrics;
  const parts = [`status HTTP ${status}`];
  if (m?.time_total) parts.push(`waktu total ${fmtSeconds(m.time_total)}`);
  if (ctx.bodySize != null) parts.push(`ukuran body ${fmtBytes(ctx.bodySize)}`);
  if (ctx.contentEncoding) parts.push(`kompresi ${ctx.contentEncoding}`);
  else parts.push('tanpa kompresi');
  const ver = ctx.final?.httpVersion;
  if (ver) parts.push(`HTTP/${ver}`);
  if (ctx.tls?.protocol) parts.push(ctx.tls.protocol);
  else if (!String(ctx.url ?? '').startsWith('https://')) parts.push('tanpa_TLS_PLACEHOLDER');
  const p3 = `Kondisi teknis: ${parts.join(', ')}.`;

  const infos = findings.filter((f) => f.severity === 'INFO' && f.suggestion).slice(0, 2);
  const p4 = infos.length
    ? `Catatan lanjutan: ${infos.map((f) => `${f.title} (${f.suggestion})`).join('; ')}.`
    : '';
  return [p1, p2, p3, p4].filter(Boolean);
}

export function buildReport({ ctx, findings, version }) {
  const stats = scoreFindings(findings);
  const summary = buildSummary({ ctx, findings, stats });
  const m = ctx.metrics;
  const tls = ctx.tls;
  return {
    tool: 'curl-analyst',
    version,
    mode: ctx.mode,
    score: stats.score,
    grade: stats.grade,
    counts: stats.counts,
    request: {
      url: ctx.url,
      method: ctx.method,
      follow: ctx.follow,
      insecure: ctx.insecure,
      hops: ctx.hopsCount,
    },
    response: {
      status: ctx.final?.status ?? 0,
      statusText: ctx.final?.statusText ?? '',
      httpVersion: ctx.final?.httpVersion ?? null,
      remoteIp: m?.remote_ip ?? null,
      contentType: ctx.headers.get('content-type'),
      contentEncoding: ctx.contentEncoding ?? null,
      sizeBytes: ctx.bodySize ?? 0,
      rawSizeBytes: ctx.bodyRawSize ?? 0,
      timeTotalSec: m?.time_total ?? null,
      timeTtfbSec: m?.time_starttransfer ?? null,
      timeDnsSec: m?.time_namelookup ?? null,
      timeConnectSec: m?.time_connect ?? null,
      redirects: m?.num_redirects ?? null,
    },
    tls: tls
      ? {
          protocol: tls.protocol ?? null,
          cipher: tls.cipher ?? null,
          authorized: tls.authorized ?? null,
          validTo: tls.validTo ?? null,
          daysLeft: tls.daysLeft ?? null,
        }
      : null,
    summary,
    findings,
  };
}

const COLORS = {
  KRITIS: '\x1b[31;1m',
  PERINGATAN: '\x1b[33m',
  INFO: '\x1b[36m',
  OK: '\x1b[32m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  reset: '\x1b[0m',
};

export function renderText(report, { color = false } = {}) {
  const c = (name, s) => (color ? `${COLORS[name]}${s}${COLORS.reset}` : s);
  const L = [];
  const r = report.response;
  L.push(c('bold', '═══ RINGKASAN ANALIS ═══'));
  L.push(`URL     : ${report.request.url}`);
  L.push(
    `Respons : ${r.status} ${r.statusText}${r.httpVersion ? ` (HTTP/${r.httpVersion})` : ''}` +
      `${r.remoteIp ? ` · ${r.remoteIp}` : ''}`,
  );
  L.push(
    `Waktu   : ${r.timeTotalSec != null ? fmtSeconds(r.timeTotalSec) : '-'} total · ` +
      `TTFB ${r.timeTtfbSec != null ? fmtSeconds(r.timeTtfbSec) : '-'}` +
      `${r.redirects ? ` · ${r.redirects} redirect` : ''}`,
  );
  L.push(
    `Body    : ${fmtBytes(r.sizeBytes)}${r.rawSizeBytes !== r.sizeBytes ? ` (mentah ${fmtBytes(r.rawSizeBytes)})` : ''}` +
      ` · ${r.contentEncoding ?? 'tanpa kompresi'}${r.contentType ? ` · ${r.contentType}` : ''}`,
  );
  L.push(
    `TLS     : ${report.tls ? `${report.tls.protocol ?? '?'}${report.tls.validTo ? ` · sertifikat s/d ${report.tls.validTo}` : ''}` : 'tidak berlaku'}`,
  );
  const gradeColor = report.score >= 75 ? 'OK' : report.score >= 55 ? 'PERINGATAN' : 'KRITIS';
  L.push(c('bold', `Skor    : ${report.score}/100 (${c(gradeColor, report.grade)})`));
  L.push('');
  L.push(c('bold', 'Narasi:'));
  for (const p of report.summary) L.push(`  ${p}`);
  if (report.ai) {
    L.push('');
    if (report.ai.ok) {
      L.push(c('bold', `NARASI AI (${report.ai.model}):`));
      for (const line of String(report.ai.narrative).split('\n')) L.push(`  ${line}`);
    } else {
      L.push(c('dim', `Narasi AI tidak tersedia: ${report.ai.error}`));
    }
  }
  L.push('');
  const ct = report.counts;
  L.push(
    c('bold', `TEMUAN (${ct.KRITIS} kritikal · ${ct.PERINGATAN} peringatan · ${ct.INFO} info · ${ct.OK} lolos)`),
  );
  L.push('');
  for (const f of report.findings) {
    if (f.severity === 'OK') {
      L.push(`  ${c('OK', '  ✓')} ${c('OK', `[OK] ${f.title}`)}`);
      continue;
    }
    L.push(`  ${c(f.severity, `[${f.severity}]`)} ${f.title}`);
    L.push(`    ${c('dim', 'kategori')} : ${f.category}`);
    if (f.evidence) L.push(`    ${c('dim', 'bukti   ')} : ${truncate(f.evidence, 300)}`);
    if (f.suggestion) L.push(`    ${c('dim', 'saran   ')} : ${f.suggestion}`);
    L.push('');
  }
  return L.join('\n');
}

export function renderJson(report) {
  return JSON.stringify(report, null, 2);
}
