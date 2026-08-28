/**
 * ============================================================
 * Romance Engine V1 — Cloudflare Worker (API Backend)
 * File: src/index.js
 * Format: ES Modules Worker
 * Binding KV: ROMANCE_KV (lihat wrangler.jsonc)
 * ============================================================
 *
 * KONTRAK API (sesuai spesifikasi romance-engine.xml §7):
 *
 *   POST /api/save
 *     Body  : application/json — RomancePayload
 *             { recipientName, message, specialDate, photoUrl?, musicUrl? }
 *     201   : { ok: true,  data: { id, viewUrl, payload } }
 *     400   : { ok: false, error: { code: "MALFORMED_JSON" | "VALIDATION_ERROR", message, details? } }
 *     405   : { ok: false, error: { code: "METHOD_NOT_ALLOWED", message } }
 *     413   : { ok: false, error: { code: "PAYLOAD_TOO_LARGE", message } }
 *     415   : { ok: false, error: { code: "UNSUPPORTED_MEDIA_TYPE", message } }
 *     500   : { ok: false, error: { code: "INTERNAL_ERROR", message } }
 *
 *   GET /api/get/:id
 *     200   : { ok: true,  data: { payload } }
 *     400   : { ok: false, error: { code: "BAD_REQUEST", message } }
 *     404   : { ok: false, error: { code: "NOT_FOUND", message } }
 *     500   : { ok: false, error: { code: "INTERNAL_ERROR", message } }
 *
 * KEPUTUSAN TEKNIS TERDOKUMENTASI (NN-007):
 *   1. KV key prefix "romance:v1:" — namespace konsisten, mencegah
 *      collision, dan memudahkan migrasi skema di masa depan.
 *   2. ID menggunakan crypto.randomUUID() dengan verifikasi ketersediaan
 *      key (maksimal 3 percobaan) sebelum KV.put.
 *   3. Body limit 64 KB, dipaksakan secara streaming (chunk reader),
 *      bukan hanya melalui header Content-Length (yang dapat dipalsukan).
 *   4. CORS allowlist: origin produksi (https://romance-engine.pages.dev)
 *      + localhost/127.0.0.1 khusus development (tanpa ini `wrangler dev`
 *      tidak dapat diuji dari frontend lokal).
 *   5. photoUrl/musicUrl hanya menerima scheme http/https. Ekstensi .mp3
 *      TIDAK dipaksakan agar URL CDN dengan query string tetap valid;
 *      kegagalan playback musik ditangani fallback audio di frontend
 *      (spesifikasi §11).
 *   6. specialDate disimpan sebagai string asli (setelah lolos validasi
 *      parse Date) untuk menghindari reinterpretasi zona waktu.
 *   7. Tidak ada TTL KV — spesifikasi tidak meminta kedaluwarsa data.
 *   8. Field di luar whitelist (id, createdAt, version) dari client
 *      diabaikan; ketiga field tersebut selalu diisi server.
 *   9. Rate limiting tidak diimplementasikan di level Worker (efektivitas
 *      per-isolate rendah); mitigasi abuse mengandalkan body limit,
 *      validasi ketat, dan dapat ditambah via Cloudflare Rate Limiting
 *      di dashboard tanpa mengubah kontrak ini.
 */

// ------------------------------------------------------------
// Konstanta konfigurasi
// ------------------------------------------------------------

const PUBLIC_FRONTEND_URL = 'https://romance-engine.pages.dev';
const KV_PREFIX = 'romance:v1:';
const PAYLOAD_SCHEMA_VERSION = 1;

const MAX_BODY_BYTES = 64 * 1024; // 64 KB
const MAX_NAME_LENGTH = 100;
const MAX_MESSAGE_LENGTH = 10_000;
const MAX_URL_LENGTH = 2_048;
const MAX_DATE_LENGTH = 64;
const MAX_ID_ATTEMPTS = 3;

// Charset ID yang diizinkan saat dibaca kembali via GET /api/get/:id.
// UUID memenuhi pola ini; pola ketat ini sekaligus mencegah karakter
// kontrol / path traversal masuk ke key KV.
const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

const ALLOWED_ORIGINS = new Set([PUBLIC_FRONTEND_URL]);
const LOCAL_DEV_ORIGIN_PATTERN = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;

// ------------------------------------------------------------
// Utilitas respons & CORS
// ------------------------------------------------------------

function isOriginAllowed(origin) {
  if (typeof origin !== 'string' || origin.length === 0) {
    return false;
  }
  if (ALLOWED_ORIGINS.has(origin)) {
    return true;
  }
  return LOCAL_DEV_ORIGIN_PATTERN.test(origin);
}

function buildCorsHeaders(origin) {
  const headers = { vary: 'Origin' };
  if (isOriginAllowed(origin)) {
    headers['access-control-allow-origin'] = origin;
  }
  return headers;
}

function jsonResponse(status, body, origin) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...buildCorsHeaders(origin),
  };
  return new Response(JSON.stringify(body), { status, headers });
}

function errorResponse(status, code, message, origin, details) {
  const body = { ok: false, error: { code, message } };
  if (Array.isArray(details) && details.length > 0) {
    body.error.details = details;
  }
  return jsonResponse(status, body, origin);
}

function handlePreflight(origin) {
  const headers = { vary: 'Origin' };
  if (isOriginAllowed(origin)) {
    headers['access-control-allow-origin'] = origin;
    headers['access-control-allow-methods'] = 'GET, POST, OPTIONS';
    headers['access-control-allow-headers'] = 'Content-Type';
    headers['access-control-max-age'] = '86400';
  }
  return new Response(null, { status: 204, headers });
}

// ------------------------------------------------------------
// Pembacaan body dengan batas ukuran (streaming)
// ------------------------------------------------------------

/**
 * Membaca body request dengan batas byte yang dipaksakan secara streaming.
 * Return: string UTF-8, atau null jika melebihi batas.
 * Decoding UTF-8 bersifat non-fatal (karakter tidak valid diganti U+FFFD)
 * agar input jahat tidak menimbulkan exception (NN-010).
 */
async function readLimitedBody(request, limitBytes) {
  if (!request.body) {
    return '';
  }

  const reader = request.body.getReader();
  const chunks = [];
  let receivedBytes = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      receivedBytes += value.byteLength;
      if (receivedBytes > limitBytes) {
        try {
          await reader.cancel();
        } catch {
          // Best-effort: pembatalan stream tidak boleh mengaburkan error 413.
        }
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const merged = new Uint8Array(receivedBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder('utf-8', { fatal: false }).decode(merged);
}

// ------------------------------------------------------------
// Validasi payload
// ------------------------------------------------------------

/**
 * Memvalidasi URL media opsional (foto/musik).
 * - undefined / null / string kosong  -> dianggap tidak diisi (null)
 * - scheme hanya http/https (memblokir javascript:, data:, vbscript:, dst.)
 * - dinormalisasi melalui URL.toString()
 */
function validateMediaUrl(value, field, errors) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'string') {
    errors.push({ field, message: `${field} harus berupa string URL atau dikosongkan.` });
    return null;
  }

  const candidate = value.trim();
  if (candidate.length === 0) {
    return null;
  }
  if (candidate.length > MAX_URL_LENGTH) {
    errors.push({ field, message: `${field} maksimal ${MAX_URL_LENGTH} karakter.` });
    return null;
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    errors.push({ field, message: `${field} bukan URL yang valid.` });
    return null;
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    errors.push({ field, message: `${field} harus menggunakan http atau https.` });
    return null;
  }

  return parsed.toString();
}

/**
 * Memvalidasi input RomancePayload dari client.
 * Hanya field dalam whitelist yang diterima; field lain diabaikan.
 * Return: { record, errors } — record null jika terdapat error.
 */
function validateRomancePayload(raw) {
  const errors = [];

  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      record: null,
      errors: [{ field: 'payload', message: 'Payload harus berupa objek JSON.' }],
    };
  }

  // recipientName — required
  let recipientName = null;
  if (typeof raw.recipientName !== 'string' || raw.recipientName.trim().length === 0) {
    errors.push({ field: 'recipientName', message: 'Nama pasangan wajib diisi.' });
  } else {
    recipientName = raw.recipientName.trim();
    if (recipientName.length > MAX_NAME_LENGTH) {
      errors.push({ field: 'recipientName', message: `Nama pasangan maksimal ${MAX_NAME_LENGTH} karakter.` });
    }
  }

  // message — required, multi-paragraf
  let declarationMessage = null;
  if (typeof raw.message !== 'string' || raw.message.trim().length === 0) {
    errors.push({ field: 'message', message: 'Pesan deklarasi wajib diisi.' });
  } else {
    declarationMessage = raw.message.trim();
    if (declarationMessage.length > MAX_MESSAGE_LENGTH) {
      errors.push({ field: 'message', message: `Pesan maksimal ${MAX_MESSAGE_LENGTH} karakter.` });
    }
  }

  // specialDate — required, harus dapat diparse sebagai Date
  let specialDate = null;
  if (typeof raw.specialDate !== 'string' || raw.specialDate.trim().length === 0) {
    errors.push({ field: 'specialDate', message: 'Tanggal spesial wajib diisi.' });
  } else {
    specialDate = raw.specialDate.trim();
    if (specialDate.length > MAX_DATE_LENGTH) {
      errors.push({ field: 'specialDate', message: `Tanggal spesial maksimal ${MAX_DATE_LENGTH} karakter.` });
    } else if (Number.isNaN(new Date(specialDate).getTime())) {
      errors.push({ field: 'specialDate', message: 'Tanggal spesial tidak valid.' });
    }
  }

  // photoUrl / musicUrl — optional, tervalidasi ketat
  const photoUrl = validateMediaUrl(raw.photoUrl, 'photoUrl', errors);
  const musicUrl = validateMediaUrl(raw.musicUrl, 'musicUrl', errors);

  if (errors.length > 0) {
    return { record: null, errors };
  }

  return {
    record: {
      recipientName,
      message: declarationMessage,
      specialDate,
      photoUrl,
      musicUrl,
    },
    errors: [],
  };
}

// ------------------------------------------------------------
// Penyimpanan KV
// ------------------------------------------------------------

/**
 * Menghasilkan unique ID, memastikan key belum terpakai, lalu menyimpan.
 * Record yang disimpan selalu berisi id + createdAt + version dari server.
 */
async function allocateAndStore(kv, record) {
  for (let attempt = 0; attempt < MAX_ID_ATTEMPTS; attempt += 1) {
    const id = crypto.randomUUID();
    const key = KV_PREFIX + id;

    const existing = await kv.get(key);
    if (existing !== null) {
      continue; // collision (sangat jarang) — coba ID baru
    }

    const stored = {
      id,
      recipientName: record.recipientName,
      message: record.message,
      specialDate: record.specialDate,
      photoUrl: record.photoUrl,
      musicUrl: record.musicUrl,
      createdAt: record.createdAt,
      version: record.version,
    };

    await kv.put(key, JSON.stringify(stored));
    return stored;
  }

  throw new Error('Unable to allocate unique id');
}

// ------------------------------------------------------------
// Handler endpoint
// ------------------------------------------------------------

async function handleSave(request, env, origin) {
  if (!env || !env.ROMANCE_KV) {
    return errorResponse(500, 'INTERNAL_ERROR', 'Layanan penyimpanan tidak tersedia. Silakan coba lagi nanti.', origin);
  }

  const contentTypeRaw = request.headers.get('content-type') || '';
  const contentType = contentTypeRaw.split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    return errorResponse(415, 'UNSUPPORTED_MEDIA_TYPE', 'Request harus berformat application/json.', origin);
  }

  const bodyText = await readLimitedBody(request, MAX_BODY_BYTES);
  if (bodyText === null) {
    return errorResponse(413, 'PAYLOAD_TOO_LARGE', `Ukuran payload melebihi batas ${MAX_BODY_BYTES / 1024} KB.`, origin);
  }

  let raw;
  try {
    raw = JSON.parse(bodyText);
  } catch {
    return errorResponse(400, 'MALFORMED_JSON', 'Body JSON tidak valid.', origin);
  }

  const { record, errors } = validateRomancePayload(raw);
  if (errors.length > 0) {
    return errorResponse(400, 'VALIDATION_ERROR', 'Data tidak valid. Periksa kembali isian Anda.', origin, errors);
  }

  record.createdAt = new Date().toISOString();
  record.version = PAYLOAD_SCHEMA_VERSION;

  let stored;
  try {
    stored = await allocateAndStore(env.ROMANCE_KV, record);
  } catch (err) {
    console.error('romance_save_failed', err);
    return errorResponse(500, 'INTERNAL_ERROR', 'Gagal menyimpan data. Silakan coba lagi.', origin);
  }

  const viewUrl = `${PUBLIC_FRONTEND_URL}/view.html?id=${encodeURIComponent(stored.id)}`;
  return jsonResponse(201, { ok: true, data: { id: stored.id, viewUrl, payload: stored } }, origin);
}

async function handleGet(env, origin, rawId) {
  if (!env || !env.ROMANCE_KV) {
    return errorResponse(500, 'INTERNAL_ERROR', 'Layanan penyimpanan tidak tersedia. Silakan coba lagi nanti.', origin);
  }

  let id;
  try {
    id = decodeURIComponent(rawId);
  } catch {
    return errorResponse(400, 'BAD_REQUEST', 'Format ID tidak valid.', origin);
  }

  if (typeof id !== 'string' || !ID_PATTERN.test(id)) {
    return errorResponse(400, 'BAD_REQUEST', 'Format ID tidak valid.', origin);
  }

  const key = KV_PREFIX + id;

  let storedText;
  try {
    storedText = await env.ROMANCE_KV.get(key);
  } catch (err) {
    console.error('romance_kv_get_failed', err);
    return errorResponse(500, 'INTERNAL_ERROR', 'Gagal mengambil data. Silakan coba lagi.', origin);
  }

  if (storedText === null) {
    return errorResponse(404, 'NOT_FOUND', 'Deklarasi dengan ID tersebut tidak ditemukan.', origin);
  }

  let payload;
  try {
    payload = JSON.parse(storedText);
  } catch (err) {
    console.error('romance_record_corrupted', err);
    return errorResponse(500, 'INTERNAL_ERROR', 'Data tidak dapat dibaca.', origin);
  }

  return jsonResponse(200, { ok: true, data: { payload } }, origin);
}

// ------------------------------------------------------------
// Entry point Worker
// ------------------------------------------------------------

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const origin = request.headers.get('origin');
      const { method } = request;
      const path = url.pathname;

      // Preflight CORS untuk seluruh endpoint.
      if (method === 'OPTIONS') {
        return handlePreflight(origin);
      }

      // POST /api/save
      if (path === '/api/save') {
        if (method !== 'POST') {
          return errorResponse(405, 'METHOD_NOT_ALLOWED', 'Endpoint ini hanya menerima metode POST.', origin);
        }
        return await handleSave(request, env, origin);
      }

      // GET /api/get/:id
      if (path.startsWith('/api/get/')) {
        if (method !== 'GET') {
          return errorResponse(405, 'METHOD_NOT_ALLOWED', 'Endpoint ini hanya menerima metode GET.', origin);
        }
        const rawId = path.slice('/api/get/'.length);
        if (rawId.length === 0) {
          return errorResponse(404, 'NOT_FOUND', 'Endpoint tidak ditemukan.', origin);
        }
        return await handleGet(env, origin, rawId);
      }

      // Di luar endpoint yang didefinisikan: 404 JSON terstruktur.
      return errorResponse(404, 'NOT_FOUND', 'Endpoint tidak ditemukan.', origin);
    } catch (err) {
      // Boundary terakhir: jangan pernah membocorkan stack trace atau
      // detail internal ke client (spesifikasi §16 error_security).
      console.error('romance_unhandled_error', err);
      let fallbackOrigin = null;
      try {
        fallbackOrigin = request.headers.get('origin');
      } catch {
        // request mungkin tidak tersedia dalam kondisi abnormal.
      }
      return errorResponse(500, 'INTERNAL_ERROR', 'Terjadi kesalahan pada server.', fallbackOrigin);
    }
  },
};