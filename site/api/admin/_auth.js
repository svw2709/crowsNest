// Shared auth for the admin endpoints.
//
// One password held in an environment variable, exchanged for a signed,
// HttpOnly session cookie. Deliberately simple: there is a single
// administrator, so a full user system would add moving parts without
// adding safety. The signing key is derived from the password, so changing
// the password immediately invalidates every existing session.

const crypto = require("crypto");

const COOKIE = "cn_admin";
const TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

const password = () => process.env.ADMIN_PASSWORD || "";

function signingKey() {
  return crypto.createHash("sha256").update("crows-nest-session|" + password()).digest();
}

const b64 = (b) => Buffer.from(b).toString("base64url");

function issueToken() {
  const body = b64(JSON.stringify({ exp: Date.now() + TTL_MS }));
  const sig = b64(crypto.createHmac("sha256", signingKey()).update(body).digest());
  return body + "." + sig;
}

function tokenValid(token) {
  if (typeof token !== "string" || !token.includes(".")) return false;
  const [body, sig] = token.split(".");
  if (!body || !sig) return false;

  const expected = b64(crypto.createHmac("sha256", signingKey()).update(body).digest());
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  try {
    const { exp } = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return typeof exp === "number" && Date.now() < exp;
  } catch {
    return false;
  }
}

function readCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    if (part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

function passwordMatches(supplied) {
  const expected = password();
  if (!expected || typeof supplied !== "string") return false;
  // Hash both sides so timingSafeEqual gets equal-length buffers regardless
  // of what was submitted, and the comparison leaks nothing about length.
  const h = (v) => crypto.createHash("sha256").update(String(v)).digest();
  return crypto.timingSafeEqual(h(supplied), h(expected));
}

const sessionCookie = (token, maxAgeSeconds) =>
  `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}`;

function isAuthed(req) {
  return tokenValid(readCookie(req, COOKIE));
}

// Guard for the data endpoints. Returns true when the caller may proceed.
function requireAuth(req, res) {
  if (!password()) {
    console.error("admin: ADMIN_PASSWORD is not set");
    res.status(500).json({ error: "Admin access is not configured." });
    return false;
  }
  if (!isAuthed(req)) {
    res.status(401).json({ error: "Please sign in." });
    return false;
  }
  return true;
}

module.exports = { COOKIE, TTL_MS, issueToken, passwordMatches, sessionCookie, isAuthed, requireAuth };
