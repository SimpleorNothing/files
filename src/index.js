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
      await env.FILES_BUCKET.put(key, request.body, {
        httpMetadata: { contentType },
      });
      return json({ ok: true });
    }

    if (method === "GET") {
      const obj = await env.FILES_BUCKET.get(key);
      if (!obj) return new Response("Not found", { status: 404 });
      const headers = new Headers();
      obj.writeHttpMetadata(headers);
      headers.set("Content-Length", String(obj.size));
      headers.set("etag", obj.httpEtag);
      const filename = key.split("/").pop();
      headers.set(
        "Content-Disposition",
        `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`
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

/* ----------------- 보안 / 세션 ----------------- */

function safeKey(raw) {
  let key;
  try {
    key = decodeURIComponent(raw);
  } catch {
    return null;
  }
  key = key.replace(/^\/+/, "").trim();
  if (!key || key.length > 1024) return null;
  if (key.includes("..") || key.includes("\0")) return null;
  return key;
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
