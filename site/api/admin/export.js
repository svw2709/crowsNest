const { requireAuth } = require("./_auth");
const { buildXlsx } = require("./_xlsx");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const PAGE = 1000; // PostgREST caps a single response, so page through.
const MAX_ROWS = 100000;

const sydney = new Intl.DateTimeFormat("en-AU", {
  timeZone: "Australia/Sydney",
  day: "2-digit", month: "2-digit", year: "numeric",
  hour: "2-digit", minute: "2-digit", hour12: false,
});

function formatSigned(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return "";
  const p = Object.fromEntries(sydney.formatToParts(d).map((x) => [x.type, x.value]));
  return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}`;
}

async function fetchAll() {
  const auth = { apikey: SERVICE_KEY, Authorization: "Bearer " + SERVICE_KEY };
  const rows = [];
  for (let from = 0; from < MAX_ROWS; from += PAGE) {
    const url =
      `${SUPABASE_URL}/rest/v1/signatures` +
      `?select=name,suburb,contact,comments,created_at&order=created_at.asc`;
    const r = await fetch(url, { headers: { ...auth, Range: `${from}-${from + PAGE - 1}` } });
    if (!r.ok) throw new Error(`supabase ${r.status}: ${await r.text().catch(() => "")}`);
    const batch = await r.json();
    rows.push(...batch);
    if (batch.length < PAGE) break;
  }
  return rows;
}

module.exports = async function handler(req, res) {
  if (!requireAuth(req, res)) return;
  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error("admin/export: Supabase env vars missing");
    return res.status(500).json({ error: "Server is not configured." });
  }

  try {
    const rows = await fetchAll();

    const file = buildXlsx({
      sheetName: "Signatures",
      headers: ["#", "Name", "Suburb", "Email or phone", "Comments", "Signed (Sydney time)"],
      widths: [6, 28, 20, 30, 60, 22],
      rows: rows.map((r, i) => [
        String(i + 1),
        r.name || "",
        r.suburb || "",
        r.contact || "",
        r.comments || "",
        formatSigned(r.created_at),
      ]),
    });

    const stamp = new Date().toISOString().slice(0, 10);
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename="crows-nest-petition-${stamp}.xlsx"`);
    res.setHeader("Content-Length", file.length);
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(file);
  } catch (err) {
    console.error("admin/export", err);
    return res.status(500).json({ error: "Couldn't build the spreadsheet. Please try again." });
  }
};
