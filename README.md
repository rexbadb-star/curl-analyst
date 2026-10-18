# curl-analyst

**AI Analyst cURL** — CLI lokal yang menjalankan cURL, menganalisis hasilnya dengan engine aturan buatan sendiri (~60 pemeriksaan), lalu mengeluarkan **ringkasan narasi ala analis + temuan berperingkat + skor kesehatan 0–100**.

100% gratis: **tanpa API berbayar, tanpa server pihak ketiga**. Mode default murni offline tanpa dependency — cukup Node.js ≥ 18 dan binary `curl`. (Opsional: naratif AI DeepSeek gratis via Puter — lihat [Analisis AI opsional](#analisis-ai-opsional-deepseek-via-puter).)

## Instalasi

```bash
cd curl-analyst
npm test          # opsional: jalankan 59 test
npm link          # opsional: bikin perintah `curl-analyst` global
```

Tanpa `npm link` pun bisa langsung: `node bin/curl-analyst.js <url>`.

## Penggunaan

### Mode utama — tool yang menjalankan cURL
```bash
curl-analyst https://example.com
curl-analyst https://api.example.com/users -H 'Authorization: Bearer TOKEN'
curl-analyst https://api.example.com/login -X POST -d '{"user":"a"}' -H 'Content-Type: application/json'
curl-analyst https://example.com/masuk -L            # ikuti redirect
curl-analyst https://example.com --json --strict     # JSON + exit 2 bila ada KRITIS
```

### Mode sekunder — analisis output yang sudah ada
```bash
curl -i https://example.com/data | curl-analyst analyze
curl-analyst analyze --file simpanan.txt
curl -i https://api.example.com/x | curl-analyst analyze --url https://api.example.com/x --json
```

### Opsi
| Flag | Fungsi |
|---|---|
| `-X, --method` | Metode HTTP (default GET; otomatis POST bila `-d` dipakai) |
| `-H, --header` | Tambah header (boleh diulang) |
| `-d, --data` | Body permintaan |
| `-L, --follow` | Ikuti redirect (default berhenti di 3xx) |
| `-k, --insecure` | Abaikan verifikasi sertifikat |
| `-t, --timeout` | Timeout per request (detik, default 30) |
| `--json` | Output JSON untuk konsumsi mesin |
| `--strict` | Exit code 2 bila ada temuan KRITIS |
| `--no-color` | Matikan warna |
| `--no-tls-probe` | Lewati probe TLS terpisah |
| `--url` | (mode analyze) URL asal untuk konteks & probe TLS |
| `--ai` | Sertakan narasi AI (DeepSeek via Puter) — lihat bagian AI |
| `--ai-model` | Ganti model AI (default `deepseek/deepseek-v4.1-flash`) |

### Kode keluar
`0` sukses · `1` request gagal/usage error · `2` `--strict` + ada KRITIS

Kegagalan AI **tidak memengaruhi kode keluar** — laporan aturan tetap menjadi penentu.

## Analisis AI opsional (DeepSeek via Puter)

Dengan flag `--ai`, laporan dilengkapi narasi AI (ringkasan + prioritas perbaikan + insight)
yang ditulis **DeepSeek** lewat [Puter.js](https://developer.puter.com/tutorials/free-unlimited-deepseek-api/)
(model *User-Pays*: biaya ditanggung akun Putermu sendiri — gratis, tanpa API key).

```bash
curl-analyst https://example.com --ai
curl-analyst https://example.com --ai --ai-model deepseek/deepseek-v4-pro --json
```

**Autentikasi (sekali saja):**
1. Set env `PUTER_AUTH_TOKEN` (token dari [puter.com/dashboard](https://puter.com/dashboard) → *Create token*), **atau**
2. Jalankan sekali dari terminal interaktif — browser membuka login Puter, token disimpan di `~/.config/curl-analyst/puter-token` (mode 0600). Bisa dioverride dengan env `CURL_ANALYST_CONFIG_DIR`.

**Perilaku:**
- Tanpa `--ai`, paket AI **tidak dimuat sama sekali** — tool tetap 100% offline.
- Gagal (tanpa token, offline, timeout 90 detik, token kedaluwarsa) → laporan aturan tetap tercetak penuh, catatan peringatan di stderr, kode keluar tidak berubah.
- **Privasi:** hanya URL, metrik, ikhtisar TLS, dan daftar temuan (cookie/authorization sudah diredaksi) yang dikirim ke Puter/DeepSeek saat `--ai` aktif. Body respons & header mentah tidak ikut.

## Yang dianalisis (8 kategori)

- **status** — 5xx, 4xx, 429 rate-limit, redirect tak diikuti, rantai panjang, downgrade HTTPS→HTTP, error semantik di balik status 2xx
- **keamanan** — HSTS, CSP, nosniff, clickjacking, Referrer/Permissions-Policy, COOP, CORS wildcard+credentials, atribut cookie (Secure/HttpOnly/SameSite), kebocoran `Server`/`X-Powered-By`
- **tls** — non-HTTPS, versi TLS (1.0/1.1 = kritikal), validitas & masa berlaku sertifikat, HSTS max-age terlalu pendek (probe handshake terpisah tanpa HTTP)
- **performa** — TTFB, total time, DNS/connect lambat, ukuran body, kompresi gzip/br hilang, HTTP/2
- **cache** — resource statis tanpa Cache-Control/ETag, HTML/JSON tanpa header cache
- **html** — doctype, `lang`, title, viewport, charset, mixed content, inline script vs CSP
- **json** — validitas (kritis bila rusak), struktur/field, indikasi pagination & field error
- **header** — Content-Type hilang/salah klaim, charset, header rate-limit

Setiap temuan punya tingkat **KRITIS / PERINGATAN / INFO / OK**, **bukti** (nilai persis dari respons), dan **saran perbaikan**.

## Skor

Mulai 100; dikurangi **−20 per KRITIS, −7 per PERINGATAN, −1 per INFO**, di-clamp 0–100.
`SEHAT ≥ 90 · BAIK ≥ 75 · PERLU PERHATIAN ≥ 55 · BERMASALAH < 55`

## Arsitektur

```
bin/curl-analyst.js   entry CLI
src/cli.js            parser argumen + orkestrasi mode run/analyze
src/exec.js           runner curl (manual redirect, -w metrics, dekompresi gzip/br/zstd)
src/parse.js          parser blok header, metrik -w, sniffing body (JSON/HTML/teks)
src/ctx.js            pembangun konteks analisis (run & tempel)
src/tlsprobe.js       probe TLS via node:tls (protokol, sertifikat, cipher)
src/rules/*.js        8 kategori aturan + registry
src/report.js         skor, generator narasi, render teks & JSON
src/ai.js             AI opsional: token Puter, prompt builder, chat DeepSeek + fallback
test/*.test.js        59 test (unit + e2e server lokal) — `node --test`
```
