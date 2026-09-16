// Petition signature endpoint.
//
// Runs server-side on Vercel so the Supabase service-role key never reaches
// the browser. The signatures table has RLS on with no policies, so this
// function is the only thing that can write to it.

const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const IP_SALT = process.env.IP_SALT || "";

const MAX_PER_IP_PER_HOUR = 5;
const LIMITS = { name: 120, suburb: 80, contact: 160, comments: 2000 };

const GENERIC_ERROR = "Sorry, something went wrong saving your signature. Please try again.";

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length) return fwd.split(",")[0].trim();
  return req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
}

function hashIp(ip) {
  return crypto.createHash("sha256").update(IP_SALT + "|" + ip).digest("hex");
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return {}; }
}

const clean = (v, max) => (typeof v === "string" ? v.trim().replace(/\s+/g, " ").slice(0, max) : "");

function contactLooksValid(contact) {
  if (contact.includes("@")) return /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(contact);
  return contact.replace(/\D/g, "").length >= 8;
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error("sign: SUPABASE_URL or SUPABASE_SERVICE_KEY is not set");
    return res.status(500).json({ error: GENERIC_ERROR });
  }

  const body = await readBody(req);

  // Honeypot. The field is hidden from people, so anything in it is a bot.
  // Return a normal-looking success so the bot has no signal to adapt to.
  if (typeof body.website === "string" && body.website.trim() !== "") {
    return res.status(200).json({ ok: true });
  }

  const name = clean(body.name, LIMITS.name);
  const suburb = clean(body.suburb, LIMITS.suburb);
  const contact = clean(body.contact, LIMITS.contact);
  const comments = clean(body.comments, LIMITS.comments);

  if (!name || !suburb || !contact) {
    return res.status(400).json({ error: "Please fill in your name, suburb, and email or phone." });
  }
  if (!contactLooksValid(contact)) {
    return res.status(400).json({ error: "That email address or phone number doesn't look quite right." });
  }

  const ipHash = hashIp(clientIp(req));
  const auth = {
    apikey: SERVICE_KEY,
    Authorization: "Bearer " + SERVICE_KEY,
  };

  // Rate limit per IP. Deliberately loose -- households, offices and cafes
  // share an address, and blocking a real signer is worse than allowing a
  // handful of extras through.
  try {
    const since = new Date(Date.now() - 3600 * 1000).toISOString();
    const url =
      `${SUPABASE_URL}/rest/v1/signatures?select=id` +
      `&ip_hash=eq.${ipHash}&created_at=gte.${encodeURIComponent(since)}`;
    const r = await fetch(url, { headers: { ...auth, Prefer: "count=exact", Range: "0-0" } });
    const recent = Number((r.headers.get("content-range") || "").split("/")[1] || 0);
    if (recent >= MAX_PER_IP_PER_HOUR) {
      return res.status(429).json({
        error: "That's a lot of signatures from one connection. Please try again in an hour.",
      });
    }
  } catch (err) {
    // A rate-limit check that fails should not stop a genuine signature.
    console.error("sign: rate-limit check failed", err);
  }

  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/signatures`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json", Prefer: "return=minimal" },
      body: JSON.stringify({
        name,
        suburb,
        contact,
        comments: comments || null,
        ip_hash: ipHash,
        user_agent: clean(req.headers["user-agent"] || "", 400),
      }),
    });

    if (r.status === 409) {
      // Unique index on the contact field -- they have already signed.
      return res.status(200).json({ ok: true, duplicate: true });
    }
    if (!r.ok) {
      console.error("sign: insert failed", r.status, await r.text().catch(() => ""));
      return res.status(500).json({ error: GENERIC_ERROR });
    }
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("sign: insert threw", err);
    return res.status(500).json({ error: GENERIC_ERROR });
  }
};
