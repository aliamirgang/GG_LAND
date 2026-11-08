const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "links.json");

if (!ADMIN_PASSWORD || !SESSION_SECRET) {
  console.error("Set ADMIN_PASSWORD and SESSION_SECRET environment variables.");
  process.exit(1);
}

app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

function readLinks() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); }
  catch { return []; }
}
function writeLinks(links) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(links, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}
function setSession(res) {
  const payload = `${Date.now() + 8 * 60 * 60 * 1000}`;
  const token = `${payload}.${sign(payload)}`;
  res.cookie("ggland_admin", token, {
    httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000, path: "/"
  });
}
function isAdmin(req) {
  const token = req.cookies?.ggland_admin;
  if (!token) return false;
  const [expiry, signature] = token.split(".");
  if (!expiry || !signature || !/^\d+$/.test(expiry)) return false;
  return Number(expiry) > Date.now() && safeEqual(signature, sign(expiry));
}
// Minimal cookie parser, avoiding another dependency.
app.use((req, res, next) => {
  req.cookies = {};
  (req.headers.cookie || "").split(";").forEach(part => {
    const i = part.indexOf("=");
    if (i > -1) req.cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  next();
});
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(401).json({ error: "ابتدا وارد پنل مدیریت شو." });
  next();
}

app.get("/api/links", (req, res) => res.json(readLinks()));

app.post("/api/login", (req, res) => {
  const password = req.body?.password || "";
  if (!safeEqual(password, ADMIN_PASSWORD)) return res.status(401).json({ error: "رمز عبور اشتباه است." });
  setSession(res);
  res.json({ ok: true });
});
app.post("/api/logout", (req, res) => {
  res.clearCookie("ggland_admin", { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production", path: "/" });
  res.json({ ok: true });
});
app.get("/api/admin-check", (req, res) => res.json({ admin: isAdmin(req) }));

app.post("/api/links", requireAdmin, (req, res) => {
  const title = String(req.body?.title || "").trim().slice(0, 60);
  const url = String(req.body?.url || "").trim();
  if (!title || !/^https?:\/\/[^\s]+$/i.test(url)) {
    return res.status(400).json({ error: "نام و لینک معتبر (با https://) وارد کن." });
  }
  const links = readLinks();
  const item = { id: crypto.randomUUID(), title, url };
  links.push(item);
  writeLinks(links);
  res.status(201).json(item);
});
app.delete("/api/links/:id", requireAdmin, (req, res) => {
  const links = readLinks();
  const next = links.filter(x => x.id !== req.params.id);
  if (next.length === links.length) return res.status(404).json({ error: "لینک پیدا نشد." });
  writeLinks(next);
  res.json({ ok: true });
});
app.put("/api/links/:id", requireAdmin, (req, res) => {
  const title = String(req.body?.title || "").trim().slice(0, 60);
  const url = String(req.body?.url || "").trim();
  if (!title || !/^https?:\/\/[^\s]+$/i.test(url)) {
    return res.status(400).json({ error: "نام و لینک معتبر (با https://) وارد کن." });
  }
  const links = readLinks();
  const item = links.find(x => x.id === req.params.id);
  if (!item) return res.status(404).json({ error: "لینک پیدا نشد." });
  item.title = title; item.url = url;
  writeLinks(links);
  res.json(item);
});

app.listen(PORT, () => console.log(`GG_LAND running on port ${PORT}`));