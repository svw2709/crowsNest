const { sessionCookie } = require("./_auth");

module.exports = async function handler(req, res) {
  res.setHeader("Set-Cookie", sessionCookie("", 0));
  return res.status(200).json({ ok: true });
};
