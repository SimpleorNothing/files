import appHtml from "./app.html";

const BASE = "/files";
const SESSION_COOKIE = "files_session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7일
const MAX_LIST = 1000;

const enc = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === BASE || path === BASE + "/") {
      return serveApp();
    }

    const apiPrefix = BASE + "/api/";
    if (path.startsWith(apiPrefix)) {
      return handleApi(request, env, path.slice(apiPrefix.length));
    }

    // /files 하위의 알 수 없는 경로 → 앱으로 폴백 (SPA)
    if (path.startsWith(BASE + "/")) {
      return serveApp();
    }

    return new Response("Not found", { status: 404 });
  },
};

function serveApp() {
  return new Response(appHtml, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
      "Cache-Control": "no-store",
    },
  });
}

async function handleApi(request, env, sub) {
  const method = request.method;

  // ---- 인증 불필요 ----
  if (sub === "login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const password = body && body.password;
    if (
      typeof password !== "string" ||
      !env.APP_PASSWORD ||
      !timingSafeEqual(password, env.APP_PASSWORD)
    ) {
      return json({ ok: false, error: "비밀번호가 올바르지 않습니다." }, 401);
    }
    const token = await createToken(env);
    return json({ ok: true }, 200, {
      "Set-Cookie": sessionCookie(token, Math.floor(SESSION_TTL_MS / 1000)),
    });
  }

  if (sub === "logout" && method === "POST") {
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
  }

  if (sub === "session" && method === "GET") {
    const ok = await verifyToken(getCookie(request, SESSION_COOKIE), env);
    return json({ authenticated: ok });
  }

  // ---- 이하 인증 필요 ----
  const authed = await verifyToken(getCookie(request, SESSION_COOKIE), env);
  if (!authed) return json({ ok: false, error: "unauthorized" }, 401);

  if (sub === "list" && method === "GET") {
    if (!env.FILES_BUCKET) return json({ ok: false, error: "R2 버킷이 연결되지 않았습니다." }, 500);
    const out = [];
    let cursor;
    do {
      const res = await env.FILES_BUCKET.list({ limit: MAX_LIST, cursor });
      for (const o of res.objects) {
        out.push({ key: o.key, size: o.size, uploaded: o.uploaded });
      }
      cursor = res.truncated ? res.cursor : undefined;
    } while (cursor);
    out.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
    return json({ ok: true, files: out });
  }

  if (sub.startsWith("file/")) {
    if (!env.FILES_BUCKET) return json({ ok: false, error: "R2 버킷이 연결되지 않았습니다." }, 500);
    const key = safeKey(sub.slice("file/".length));
    if (!key) return json({ ok: false, error: "잘못된 파일 이름입니다." }, 400);

    if (method === "PUT") {
      const contentType = request.headers.get("Content-Type") || "application/octet-stream";
      const bytes = new Uint8Array(await request.arrayBuffer());

      // 명시적 분류(회사/개인 탭)는 그대로, 그 외에는 제목+내용으로 자동 분류
      let finalKey = key;
      if (!key.startsWith("company/") && !key.startsWith("personal/")) {
        const filename = key.split("/").pop();
        let text = filename;
        try {
          text += " " + (await extractText(filename, bytes));
        } catch {}
        const cat = classifyText(text);
        if (cat !== "none") finalKey = cat + "/" + key;
      }

      await env.FILES_BUCKET.put(finalKey, bytes, { httpMetadata: { contentType } });
      return json({ ok: true, key: finalKey });
    }

    if (method === "GET") {
      const obj = await env.FILES_BUCKET.get(key);
      if (!obj) return new Response("Not found", { status: 404 });
      const headers = new Headers();
      obj.writeHttpMetadata(headers);
      headers.set("Content-Length", String(obj.size));
      headers.set("etag", obj.httpEtag);
      const filename = key.split("/").pop();
      // ?inline=1 이면 새 탭에서 미리보기, 아니면 다운로드
      const inline = new URL(request.url).searchParams.has("inline");
      headers.set(
        "Content-Disposition",
        `${inline ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(filename)}`
      );
      headers.set("Cache-Control", "private, no-store");
      headers.set("X-Content-Type-Options", "nosniff");
      return new Response(obj.body, { headers });
    }

    if (method === "DELETE") {
      await env.FILES_BUCKET.delete(key);
      return json({ ok: true });
    }
  }

  return json({ ok: false, error: "not found" }, 404);
}

/* ----------------- 자동 분류 (제목 + 내용) ----------------- */

const CLASSIFY = {
  company: [
    "경쟁사", "분석", "동향", "공장", "시장", "공급망", "부품", "검증", "활용", "공조",
    "가전", "보고서", "실적", "매출", "전략", "회의록", "회의", "업무", "프로젝트", "계약",
    "거래처", "사업", "제품", "영업", "기획", "보고", "생산", "품질", "lg", "삼성", "midea",
    "cr_op", "kpi", "회사",
  ],
  personal: [
    "개인", "가족", "여행", "사진", "이력서", "가계부", "일기", "청구서", "보험", "의료",
    "진료", "영수증", "통장", "급여", "명세서", "주민등록", "신분증", "연말정산",
    "청첩장", "부고", "생일", "메모", "건강검진", "처방", "예약",
  ],
};

function classifyText(text) {
  const n = (text || "").toLowerCase();
  const isC = CLASSIFY.company.some((kw) => n.includes(kw));
  const isP = CLASSIFY.personal.some((kw) => n.includes(kw));
  if (isC && !isP) return "company";
  if (isP && !isC) return "personal";
  return "none"; // 둘 다이거나 둘 다 아니면 미분류
}

const TEXT_EXT = /\.(txt|md|markdown|csv|tsv|json|xml|html?|log|rtf|yaml|yml|ini|js|ts|css)$/i;
const OOXML_EXT = /\.(docx|xlsx|pptx)$/i;

async function extractText(filename, bytes) {
  if (TEXT_EXT.test(filename)) {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes).slice(0, 200000);
  }
  if (OOXML_EXT.test(filename)) {
    return await extractOoxmlText(bytes);
  }
  return "";
}

function stripTags(s) {
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
}

async function extractOoxmlText(bytes) {
  const entries = readZipEntries(bytes);
  const wanted = Object.keys(entries).filter(
    (n) =>
      n === "word/document.xml" ||
      n.startsWith("ppt/slides/slide") ||
      n === "xl/sharedStrings.xml" ||
      n.startsWith("xl/worksheets/sheet")
  );
  let out = "";
  for (const name of wanted) {
    try {
      const data = await inflateEntry(bytes, entries[name]);
      out += " " + stripTags(new TextDecoder("utf-8", { fatal: false }).decode(data));
    } catch {}
    if (out.length > 200000) break;
  }
  return out;
}

function readZipEntries(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let eocd = -1;
  const minStart = Math.max(0, buf.length - 22 - 65536);
  for (let i = buf.length - 22; i >= minStart; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("EOCD not found");
  const cdCount = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const entries = {};
  for (let i = 0; i < cdCount; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const compSize = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const localOffset = dv.getUint32(p + 42, true);
    const name = new TextDecoder().decode(buf.subarray(p + 46, p + 46 + nameLen));
    entries[name] = { method, compSize, localOffset };
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

async function inflateEntry(buf, e) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const nameLen = dv.getUint16(e.localOffset + 26, true);
  const extraLen = dv.getUint16(e.localOffset + 28, true);
  const start = e.localOffset + 30 + nameLen + extraLen;
  const comp = buf.subarray(start, start + e.compSize);
  if (e.method === 0) return comp; // 저장(무압축)
  if (e.method === 8) {
    const stream = new Response(comp).body.pipeThrough(new DecompressionStream("deflate-raw"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
  throw new Error("unsupported zip method " + e.method);
}

/* ----------------- 보안 / 세션 ----------------- */

function validateKey(key) {
  if (typeof key !== "string") return null;
  key = key.replace(/^\/+/, "").trim();
  if (!key || key.length > 1024) return null;
  if (key.includes("..") || key.includes("\0")) return null;
  return key;
}

function safeKey(raw) {
  let key;
  try {
    key = decodeURIComponent(raw);
  } catch {
    return null;
  }
  return validateKey(key);
}

async function createToken(env) {
  const exp = Date.now() + SESSION_TTL_MS;
  const payload = String(exp);
  const sig = await hmac(payload, env.SESSION_SECRET);
  return payload + "." + sig;
}

async function verifyToken(token, env) {
  if (!token || !env.SESSION_SECRET) return false;
  const idx = token.lastIndexOf(".");
  if (idx <= 0) return false;
  const payload = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = await hmac(payload, env.SESSION_SECRET);
  if (!timingSafeEqual(sig, expected)) return false;
  const exp = Number(payload);
  return Number.isFinite(exp) && Date.now() < exp;
}

async function hmac(data, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return base64url(sig);
}

function base64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function timingSafeEqual(a, b) {
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let result = 0;
  for (let i = 0; i < ab.length; i++) result |= ab[i] ^ bb[i];
  return result === 0;
}

function sessionCookie(token, maxAgeSec) {
  return [
    `${SESSION_COOKIE}=${token}`,
    `Path=${BASE}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAgeSec}`,
  ].join("; ");
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? m[1] : null;
}

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}
