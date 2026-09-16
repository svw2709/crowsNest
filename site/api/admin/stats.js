const { requireAuth, isAuthed } = require("./_auth");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

module.exports = async function handler(req, res) {
  // Used by the page on load to decide whether to show the login form,
  // so an unauthenticated caller gets a plain answer rather than an error.
  if (!isAuthed(req)) return res.status(200).json({ authed: false });
  if (!requireAuth(req, res)) return;

  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/signatures?select=id`, {
      headers: {
        apikey: SERVICE_KEY,
        Authorization: "Bearer " + SERVICE_KEY,
        Prefer: "count=exact",
        Range: "0-0",
      },
    });
    const total = Number((r.headers.get("content-range") || "").split("/")[1] || 0);
    return res.status(200).json({ authed: true, total });
  } catch (err) {
    console.error("admin/stats", err);
    return res.status(500).json({ error: "Couldn't read the signature count." });
  }
};
