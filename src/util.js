export function fmtBytes(n) {
  if (n == null || Number.isNaN(n)) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = i === 0 || v >= 100 ? 0 : 1;
  return `${v.toFixed(digits)} ${units[i]}`;
}

export function fmtSeconds(s) {
  if (s == null || Number.isNaN(s)) return '-';
  const ms = s * 1000;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function truncate(s, max = 180) {
  if (s == null) return '';
  const str = String(s);
  return str.length > max ? `${str.slice(0, max - 1)}…` : str;
}
