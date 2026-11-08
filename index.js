/*!
 * YIFile 本地解密下载 — Gopeed 扩展
 *
 * 原理(与 yifile.com 官方 down.html 页面完全一致):
 *   1. down.html#url=<CDN密文链接>&k=<密钥>&name=<文件名>
 *   2. 密文 = AES-256-CTR 加密, 每 50MiB 一个分片:
 *        key      = SHA-256("PWD|" + k)
 *        counter  = SHA-256("CTR|" + k) 前 16 字节, 低 4 字节 = be32(分片序号 + 片内块号)
 *   3. 本扩展让 Gopeed 核心直接 Range 拉密文(CDN 支持分段), 扩展本地边收边解密,
 *      再以明文流交回下载器存盘 —— 服务器零流量, 手机本地解密。
 *
 * 需要支持 blob 数据流 API 的 Gopeed 版本(main 分支 2026-07-14 #1407 之后)。
 */
'use strict';

var CHUNK_SIZE = 50 * 1024 * 1024; // 必须和上传端一致: 50MB

var TEXT_ENCODER = new TextEncoder();

/* ============================ SHA-256 ============================ */
var SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function sha256Rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function sha256Bytes(input) {
  var len = input.length;
  var bitLen = len * 8;
  var paddedLen = ((len + 8) >> 6 << 6) + 64;
  var m = new Uint8Array(paddedLen);
  m.set(input);
  m[len] = 0x80;
  var hi = Math.floor(bitLen / 4294967296);
  var lo = bitLen >>> 0;
  m[paddedLen - 8] = (hi >>> 24) & 0xff;
  m[paddedLen - 7] = (hi >>> 16) & 0xff;
  m[paddedLen - 6] = (hi >>> 8) & 0xff;
  m[paddedLen - 5] = hi & 0xff;
  m[paddedLen - 4] = (lo >>> 24) & 0xff;
  m[paddedLen - 3] = (lo >>> 16) & 0xff;
  m[paddedLen - 2] = (lo >>> 8) & 0xff;
  m[paddedLen - 1] = lo & 0xff;

  var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  var h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  var w = new Uint32Array(64);

  for (var off = 0; off < paddedLen; off += 64) {
    for (var i = 0; i < 16; i++) {
      var j = off + i * 4;
      w[i] = ((m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3]) >>> 0;
    }
    for (i = 16; i < 64; i++) {
      var s0 = sha256Rotr(w[i - 15], 7) ^ sha256Rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      var s1 = sha256Rotr(w[i - 2], 17) ^ sha256Rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (i = 0; i < 64; i++) {
      var S1 = sha256Rotr(e, 6) ^ sha256Rotr(e, 11) ^ sha256Rotr(e, 25);
      var ch = (e & f) ^ ((~e) & g);
      var t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      var S0 = sha256Rotr(a, 2) ^ sha256Rotr(a, 13) ^ sha256Rotr(a, 22);
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  var out = new Uint8Array(32);
  var vals = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (var k = 0; k < 8; k++) {
    out[k * 4] = (vals[k] >>> 24) & 0xff;
    out[k * 4 + 1] = (vals[k] >>> 16) & 0xff;
    out[k * 4 + 2] = (vals[k] >>> 8) & 0xff;
    out[k * 4 + 3] = vals[k] & 0xff;
  }
  return out;
}

/* ============================ AES-256 ============================ */
var SBOX = new Uint8Array(256);
var M2 = new Uint8Array(256), M3 = new Uint8Array(256);
var M9 = new Uint8Array(256), M11 = new Uint8Array(256), M13 = new Uint8Array(256), M14 = new Uint8Array(256);

function gfMul(a, b) {
  var p = 0;
  for (var i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>>= 1;
  }
  return p;
}

(function initAesTables() {
  for (var i = 1; i < 256; i++) {
    var inv = 0;
    for (var x = 1; x < 256; x++) {
      if (gfMul(i, x) === 1) { inv = x; break; }
    }
    var b = inv;
    var s = b
      ^ (((b << 1) | (b >>> 7)) & 0xff)
      ^ (((b << 2) | (b >>> 6)) & 0xff)
      ^ (((b << 3) | (b >>> 5)) & 0xff)
      ^ (((b << 4) | (b >>> 4)) & 0xff)
      ^ 0x63;
    SBOX[i] = s & 0xff;
    M2[i] = gfMul(i, 2); M3[i] = gfMul(i, 3);
    M9[i] = gfMul(i, 9); M11[i] = gfMul(i, 11);
    M13[i] = gfMul(i, 13); M14[i] = gfMul(i, 14);
  }
  SBOX[0] = 0x63;
})();

var AES_S = new Uint8Array(16);
var AES_T = new Uint8Array(16);

function aesExpandKey(key32) {
  var sched = new Uint8Array(240);
  for (var i = 0; i < 32; i++) sched[i] = key32[i];
  var rcon = 1;
  for (i = 8; i < 60; i++) {
    var base = (i - 1) * 4;
    var t0 = sched[base], t1 = sched[base + 1], t2 = sched[base + 2], t3 = sched[base + 3];
    if (i % 8 === 0) {
      var u0 = SBOX[t1] ^ rcon;
      var u1 = SBOX[t2];
      var u2 = SBOX[t3];
      var u3 = SBOX[t0];
      rcon = ((rcon << 1) ^ ((rcon & 0x80) ? 0x11b : 0)) & 0xff;
      t0 = u0; t1 = u1; t2 = u2; t3 = u3;
    } else if (i % 8 === 4) {
      t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3];
    }
    var prev = (i - 8) * 4;
    var idx = i * 4;
    sched[idx] = sched[prev] ^ t0;
    sched[idx + 1] = sched[prev + 1] ^ t1;
    sched[idx + 2] = sched[prev + 2] ^ t2;
    sched[idx + 3] = sched[prev + 3] ^ t3;
  }
  return sched;
}

function aesEncryptBlock(out, sched, state) {
  for (var i = 0; i < 16; i++) AES_S[i] = state[i] ^ sched[i];
  for (var r = 1; r < 14; r++) {
    AES_T[0] = SBOX[AES_S[0]]; AES_T[4] = SBOX[AES_S[4]]; AES_T[8] = SBOX[AES_S[8]]; AES_T[12] = SBOX[AES_S[12]];
    AES_T[1] = SBOX[AES_S[5]]; AES_T[5] = SBOX[AES_S[9]]; AES_T[9] = SBOX[AES_S[13]]; AES_T[13] = SBOX[AES_S[1]];
    AES_T[2] = SBOX[AES_S[10]]; AES_T[6] = SBOX[AES_S[14]]; AES_T[10] = SBOX[AES_S[2]]; AES_T[14] = SBOX[AES_S[6]];
    AES_T[3] = SBOX[AES_S[15]]; AES_T[7] = SBOX[AES_S[3]]; AES_T[11] = SBOX[AES_S[7]]; AES_T[15] = SBOX[AES_S[11]];
    var k = r * 16;
    for (var col = 0; col < 4; col++) {
      var base = col * 4;
      var a0 = AES_T[base], a1 = AES_T[base + 1], a2 = AES_T[base + 2], a3 = AES_T[base + 3];
      AES_S[base] = M2[a0] ^ M3[a1] ^ a2 ^ a3 ^ sched[k + base];
      AES_S[base + 1] = a0 ^ M2[a1] ^ M3[a2] ^ a3 ^ sched[k + base + 1];
      AES_S[base + 2] = a0 ^ a1 ^ M2[a2] ^ M3[a3] ^ sched[k + base + 2];
      AES_S[base + 3] = M3[a0] ^ a1 ^ a2 ^ M2[a3] ^ sched[k + base + 3];
    }
  }
  out[0] = SBOX[AES_S[0]] ^ sched[224];
  out[4] = SBOX[AES_S[4]] ^ sched[228];
  out[8] = SBOX[AES_S[8]] ^ sched[232];
  out[12] = SBOX[AES_S[12]] ^ sched[236];
  out[1] = SBOX[AES_S[5]] ^ sched[225];
  out[5] = SBOX[AES_S[9]] ^ sched[229];
  out[9] = SBOX[AES_S[13]] ^ sched[233];
  out[13] = SBOX[AES_S[1]] ^ sched[237];
  out[2] = SBOX[AES_S[10]] ^ sched[226];
  out[6] = SBOX[AES_S[14]] ^ sched[230];
  out[10] = SBOX[AES_S[2]] ^ sched[234];
  out[14] = SBOX[AES_S[6]] ^ sched[238];
  out[3] = SBOX[AES_S[15]] ^ sched[227];
  out[7] = SBOX[AES_S[3]] ^ sched[231];
  out[11] = SBOX[AES_S[7]] ^ sched[235];
  out[15] = SBOX[AES_S[11]] ^ sched[239];
}

/* ==================== YIFile 密钥派生(对齐官方 down.html) ==================== */
var KS_TMP = new Uint8Array(16);
var CTR_TMP = new Uint8Array(16);

function deriveKey(k) {
  return sha256Bytes(TEXT_ENCODER.encode('PWD|' + k));
}

function deriveBaseCounter(k) {
  return sha256Bytes(TEXT_ENCODER.encode('CTR|' + k)).subarray(0, 16);
}

function fillKeystream(baseCtr, sched, blockStart) {
  var chunkIdx = Math.floor(blockStart / CHUNK_SIZE);
  var blockInChunk = Math.floor((blockStart - chunkIdx * CHUNK_SIZE) / 16);
  var v = (chunkIdx + blockInChunk) >>> 0;
  CTR_TMP.set(baseCtr, 0);
  CTR_TMP[12] = (v >>> 24) & 0xff;
  CTR_TMP[13] = (v >>> 16) & 0xff;
  CTR_TMP[14] = (v >>> 8) & 0xff;
  CTR_TMP[15] = v & 0xff;
  aesEncryptBlock(KS_TMP, sched, CTR_TMP);
  return KS_TMP;
}

function decryptRange(cipher, startAbs, baseCtr, sched) {
  var out = new Uint8Array(cipher.length);
  var pos = 0;
  while (pos < cipher.length) {
    var p = startAbs + pos;
    var bs = p - (p & 15);
    var ks = fillKeystream(baseCtr, sched, bs);
    var off = p & 15;
    var n = 16 - off;
    if (n > cipher.length - pos) n = cipher.length - pos;
    for (var j = 0; j < n; j++) out[pos + j] = cipher[pos + j] ^ ks[off + j];
    pos += n;
  }
  return out;
}

/* ============================ 链接解析 ============================ */
function parseYifileHash(rawUrl) {
  var out = {};
  var hashIdx = rawUrl.indexOf('#');
  if (hashIdx < 0) return out;
  var hash = rawUrl.slice(hashIdx + 1);
  if (!hash) return out;
  var pairs = hash.split('&');
  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i];
    var eq = pair.indexOf('=');
    if (eq <= 0) continue;
    var key = pair.slice(0, eq);
    var value = pair.slice(eq + 1);
    try { value = decodeURIComponent(value.replace(/\+/g, ' ')); } catch (e) { /* keep raw */ }
    out[key] = value;
  }
  return out;
}

function sanitizeFileName(name) {
  var n = String(name || '').replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').replace(/\.+$/, '').trim();
  if (!n) n = 'download.bin';
  if (n.length > 150) n = n.slice(-150);
  return n;
}

/* ============================ 网络 ============================ */
var WEB_UA = 'Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36';
var CLIENT_UA = 'okhttp/4.12.0 YifileDesktop/0.1';

function baseHeaders(mode) {
  if (mode === 'okhttp') return { 'User-Agent': CLIENT_UA };
  return { 'User-Agent': WEB_UA, 'Referer': 'https://www.yifile.com/' };
}

function mergeHeaders(mode, extra) {
  var out = baseHeaders(mode);
  var ek = Object.keys(extra || {});
  for (var i = 0; i < ek.length; i++) out[ek[i]] = extra[ek[i]];
  return out;
}

function probeSize(cdnUrl, opts) {
  var mode = (opts && opts.ua) === 'okhttp' ? 'okhttp' : 'web';
  return fetch(cdnUrl, { headers: mergeHeaders(mode, { Range: 'bytes=0-0' }) }).then(function (resp) {
    var total = 0;
    var cr = '' + ((resp.headers && resp.headers.get) ? resp.headers.get('content-range') : '');
    var m = /\/\s*(\d+)\s*$/.exec(cr);
    if (m) {
      total = parseInt(m[1], 10);
    } else {
      var cl = (resp.headers && resp.headers.get) ? resp.headers.get('content-length') : '';
      if (cl) total = parseInt(cl, 10);
    }
    if (resp.body && resp.body.cancel) { try { resp.body.cancel(); } catch (e) {} }
    else if (resp.body && resp.body.getReader) { try { resp.body.getReader().cancel(); } catch (e) {} }
    return total;
  }).catch(function () { return 0; });
}

function sleepMs(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// read() + 无数据超时: 超时返回 {stalled:true}, 不等待底层 fetch 自行断开。
function readWithStall(reader, ms) {
  return new Promise(function (resolve) {
    var timer = setTimeout(function () { resolve({ stalled: true }); }, ms);
    reader.read().then(
      function (r) { clearTimeout(timer); resolve({ stalled: false, r: r }); },
      function (e) { clearTimeout(timer); resolve({ stalled: false, error: e }); }
    );
  });
}

// 断流自愈下载流:
//   - 每次 read 都带 stall 超时(默认 15s), 无数据立即放弃当前 fetch;
//   - 从已收字节 abs 重新 Range(链支持任意偏移 206), 1s 起指数退避到 15s 封顶;
//   - Gopeed 核心只看到连续明文流, 不感知断开。
function createDecryptStream(cdnUrl, baseCtr, sched, offset, end, opts) {
  opts = opts || {};
  var mode = opts.ua === 'okhttp' ? 'okhttp' : 'web';
  var stallMs = typeof opts.stallMs === 'number' && opts.stallMs >= 0 ? opts.stallMs : 15000;
  var backoffStart = typeof opts.backoffStart === 'number' && opts.backoffStart >= 0 ? opts.backoffStart : 1000;
  var maxBackoff = typeof opts.maxBackoff === 'number' && opts.maxBackoff > 0 ? opts.maxBackoff : 15000;
  var stopped = false;
  return new ReadableStream({
    async start(controller) {
      var abs = offset || 0;
      var backoff = backoffStart;
      while (!stopped) {
        var resp = null, reader = null, failed = null;
        try {
          resp = await fetch(cdnUrl, { headers: mergeHeaders(mode, { Range: 'bytes=' + abs + '-' + (end >= 0 ? end : '') }) });
          if (!resp.ok) throw new Error('CDN HTTP ' + resp.status + ' (offset=' + abs + ')');
          reader = resp.body.getReader();
          while (!stopped) {
            var sr = await readWithStall(reader, stallMs);
            if (sr.stalled) { failed = new Error('CDN 断流 (offset=' + abs + ')'); break; }
            if (sr.error) { failed = sr.error; break; }
            var r = sr.r;
            if (r.done) { controller.close(); return; }
            var v = r.value;
            if (!v || !v.length) continue;
            var plain = decryptRange(v, abs, baseCtr, sched);
            abs += v.length;
            controller.enqueue(plain);
          }
        } catch (e) { failed = e; }
        if (reader) { try { reader.cancel(); } catch (e) {} }
        if (stopped) return;
        await sleepMs(backoff);
        backoff = Math.min(maxBackoff, backoff * 2);
      }
    },
    cancel() { stopped = true; }
  });
}

/* ============================ 入口 ============================ */
if (typeof gopeed !== 'undefined' && gopeed && gopeed.events && gopeed.events.onResolve) {
  gopeed.events.onResolve(async function (ctx) {
    try {
      var raw = String(ctx.req.url || '').trim();
      var q = parseYifileHash(raw);
      if (!q.url || !q.k) {
        throw new Error('YIFile 链接缺少 url/k 参数, 请使用解析页返回的 down.html 链接');
      }
      if (!gopeed.runtime || !gopeed.runtime.blob || !gopeed.runtime.blob.createObjectURL) {
        throw new Error('当前 Gopeed 版本不支持 blob 数据流 API, 请升级到 2026-07 之后的新版本');
      }
      var cdnUrl = q.url;
      var name = sanitizeFileName(q.name);
      var key = deriveKey(q.k);
      var baseCtr = deriveBaseCounter(q.k);
      var sched = aesExpandKey(key);

      var streamOpts = { ua: q.ua === 'okhttp' ? 'okhttp' : 'web' };

      var size = await probeSize(cdnUrl, streamOpts);
      if (!size) throw new Error('无法获取 YIFile CDN 文件大小, 链接可能已过期');

      // 单连接交付: vip6 CDN 对同一链的多 Range 并发会限速(实测 2 并发单流仅 ~50KB/s),
      // 因此不让 Gopeed 分段多连接, 由扩展内部单流下载 + 断流自愈续传。
      var SINGLE_CONNECTION = true;

      var blobUrl = gopeed.runtime.blob.createObjectURL(async function (opts) {
        var o = opts || {};
        return createDecryptStream(cdnUrl, baseCtr, sched, o.offset || 0, typeof o.end === 'number' ? o.end : -1, streamOpts);
      }, { size: size, range: !SINGLE_CONNECTION });

      ctx.res = {
        name: name,
        range: !SINGLE_CONNECTION,
        files: [
          { name: name, size: size, req: { url: blobUrl } }
        ]
      };
    } catch (e) {
      if (gopeed.logger && gopeed.logger.error) gopeed.logger.error('[yifile] ' + ((e && e.message) || e));
      throw e;
    }
  });
}

/* ============================ 测试导出 ============================ */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    CHUNK_SIZE: CHUNK_SIZE,
    sha256Bytes: sha256Bytes,
    aesExpandKey: aesExpandKey,
    aesEncryptBlock: aesEncryptBlock,
    deriveKey: deriveKey,
    deriveBaseCounter: deriveBaseCounter,
    decryptRange: decryptRange,
    parseYifileHash: parseYifileHash,
    sanitizeFileName: sanitizeFileName,
    createDecryptStream: createDecryptStream,
    probeSize: probeSize,
    readWithStall: readWithStall,
    sleepMs: sleepMs,
    baseHeaders: baseHeaders,
    WEB_UA: WEB_UA,
    CLIENT_UA: CLIENT_UA
  };
}

