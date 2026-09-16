const { issueToken, passwordMatches, sessionCookie, TTL_MS } = require("./_auth");

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  if (!process.env.ADMIN_PASSWORD) {
    console.error("admin/login: ADMIN_PASSWORD is not set");
    return res.status(500).json({ error: "Admin access is not configured." });
  }

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch { body = {}; } }
  if (!body || typeof body !== "object") body = {};

  if (!passwordMatches(body.password)) {
    // Slow every failure down. Combined with a strong password this makes
    // guessing over the network impractical, without needing shared state
    // between serverless invocations.
    await new Promise((r) => setTimeout(r, 1000));
    return res.status(401).json({ error: "That password isn't right." });
  }

  res.setHeader("Set-Cookie", sessionCookie(issueToken(), Math.floor(TTL_MS / 1000)));
  return res.status(200).json({ ok: true });
};
