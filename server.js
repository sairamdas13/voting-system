require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { MongoClient } = require("mongodb");

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017";
const OFFICER_KEY = process.env.OFFICER_KEY || "";   // secret key needed to register as officer
const DB_NAME = "votingdb";
const PARTIES = ["BJP", "CONGRESS", "NOTA"];
const SESSION_MS = 2 * 60 * 60 * 1000;               // 2 hours
const ID_RE = /^[A-Za-z0-9_-]{3,20}$/;

// ---------- password hashing (scrypt + random salt) ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return `${salt}:${crypto.scryptSync(pw, salt, 32).toString("hex")}`;
}
function checkPassword(pw, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  const a = crypto.scryptSync(pw, salt, 32);
  const b = Buffer.from(hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- sessions (in memory) ----------
const sessions = new Map();
function newSession(role, id, name) {
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, { role, id, name, exp: Date.now() + SESSION_MS });
  return token;
}
function getSession(token, role) {
  const s = sessions.get(token);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(token); return null; }
  return !role || s.role === role ? s : null;
}
setInterval(() => { for (const [t, s] of sessions) if (s.exp < Date.now()) sessions.delete(t); }, 600000).unref();

// ---------- simple brute-force lock: 5 failures = 10 minute lock ----------
const fails = new Map();
const isLocked = (k) => { const f = fails.get(k); return !!f && f.until > Date.now() && f.n >= 5; };
const recordFail = (k) => {
  const f = fails.get(k);
  const cur = f && f.until > Date.now() ? f : { n: 0 };
  cur.n++; cur.until = Date.now() + 600000; fails.set(k, cur);
};

// ---------- helpers ----------
const q = (req, k) => (typeof req.query[k] === "string" ? req.query[k] : "");
const cleanId = (v) => String(v || "").trim().toUpperCase();
function validateAccount(id, name, password) {
  if (!ID_RE.test(id)) return "ID must be 3 to 20 characters: letters, numbers, - or _.";
  if (name.length < 2 || name.length > 50) return "Enter the full name (2 to 50 characters).";
  if (password.length < 6 || password.length > 64) return "Password must be 6 to 64 characters.";
  return null;
}
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ ok: false, message: "Server error. Please try again." });
  });
function needOfficer(req, res) {
  const s = getSession(q(req, "token"), "officer");
  if (!s) res.status(401).json({ ok: false, expired: true, message: "Session expired. Please log in again." });
  return s;
}

const app = express();
app.disable("x-powered-by");
app.use(express.static(path.join(__dirname, "public")));

(async () => {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const db = client.db(DB_NAME);
  const votes = db.collection("votes");
  const voters = db.collection("voters");
  const officers = db.collection("officers");

  await Promise.all([
    votes.createIndex({ voterId: 1 }, { unique: true }),     // one vote per voter
    voters.createIndex({ voterId: 1 }, { unique: true }),
    officers.createIndex({ officerId: 1 }, { unique: true }),
  ]);
  console.log("Connected to MongoDB");
  if (!OFFICER_KEY) console.log("WARNING: OFFICER_KEY is not set in .env, officer registration is disabled.");

  // ================= LOGIN (voter or officer) =================
  // GET /api/login?role=voter|officer&id=...&password=...
  app.get("/api/login", wrap(async (req, res) => {
    const role = q(req, "role");
    const id = cleanId(q(req, "id"));
    const password = q(req, "password");
    if (!["voter", "officer"].includes(role)) {
      return res.status(400).json({ ok: false, message: "Choose how you want to log in." });
    }
    const lockKey = `${req.ip}|${role}|${id}`;
    if (isLocked(lockKey)) {
      return res.status(429).json({ ok: false, message: "Too many failed attempts. Try again after 10 minutes." });
    }
    const coll = role === "voter" ? voters : officers;
    const field = role === "voter" ? "voterId" : "officerId";
    const user = ID_RE.test(id) ? await coll.findOne({ [field]: id }) : null;
    if (!user || !checkPassword(password, user.passwordHash)) {
      recordFail(lockKey);
      return res.status(401).json({ ok: false, message: "Invalid ID or password." });
    }
    fails.delete(lockKey);
    const out = { ok: true, token: newSession(role, id, user.name), role, id, name: user.name };
    if (role === "voter") out.alreadyVoted = !!(await votes.findOne({ voterId: id }));
    res.json(out);
  }));

  // GET /api/logout?token=...
  app.get("/api/logout", (req, res) => {
    sessions.delete(q(req, "token"));
    res.json({ ok: true });
  });

  // ================= VOTING (voters only) =================
  // GET /api/vote?token=...&party=BJP
  app.get("/api/vote", wrap(async (req, res) => {
    const s = getSession(q(req, "token"), "voter");
    if (!s) return res.status(401).json({ ok: false, expired: true, message: "Session expired. Please log in again." });

    const party = q(req, "party").toUpperCase();
    if (!PARTIES.includes(party)) return res.status(400).json({ ok: false, message: "Invalid option." });

    // the voter must still be on the list (officer may have deleted them)
    if (!(await voters.findOne({ voterId: s.id }))) {
      sessions.delete(q(req, "token"));
      return res.status(403).json({ ok: false, expired: true, message: "You are not on the voters list." });
    }
    try {
      await votes.insertOne({ voterId: s.id, party, time: new Date() });
      res.json({ ok: true, message: `Your vote for ${party} has been recorded.` });
    } catch (err) {
      if (err.code === 11000) return res.json({ ok: false, alreadyVoted: true, message: "You already voted." });
      throw err;
    }
  }));

  // ================= OFFICER ONLY =================
  // GET /api/officer/register?key=...&id=...&name=...&password=...
  app.get("/api/officer/register", wrap(async (req, res) => {
    if (!OFFICER_KEY) {
      return res.status(503).json({ ok: false, message: "Officer registration is switched off. Set OFFICER_KEY in the .env file." });
    }
    const keyLock = `${req.ip}|officerkey`;
    if (isLocked(keyLock)) {
      return res.status(429).json({ ok: false, message: "Too many wrong keys. Try again after 10 minutes." });
    }
    const sha = (x) => crypto.createHash("sha256").update(x).digest();
    if (!crypto.timingSafeEqual(sha(q(req, "key")), sha(OFFICER_KEY))) {
      recordFail(keyLock);
      return res.status(403).json({ ok: false, message: "Invalid officer registration key." });
    }
    const id = cleanId(q(req, "id")), name = q(req, "name").trim(), password = q(req, "password");
    const bad = validateAccount(id, name, password);
    if (bad) return res.status(400).json({ ok: false, message: bad });
    try {
      await officers.insertOne({ officerId: id, name, passwordHash: hashPassword(password), createdAt: new Date() });
      res.json({ ok: true, message: "Officer registered. You can log in now." });
    } catch (err) {
      if (err.code === 11000) return res.status(409).json({ ok: false, message: "This officer ID already exists." });
      throw err;
    }
  }));

  // GET /api/officer/results?token=...
  app.get("/api/officer/results", wrap(async (req, res) => {
    if (!needOfficer(req, res)) return;
    const counts = {};
    await Promise.all(PARTIES.map(async (p) => { counts[p] = await votes.countDocuments({ party: p }); }));
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    res.json({ ok: true, counts, total, registered: await voters.countDocuments() });
  }));

  // GET /api/officer/voters?token=...   (shows who has voted, never whom they voted for)
  app.get("/api/officer/voters", wrap(async (req, res) => {
    if (!needOfficer(req, res)) return;
    const list = await voters.find({}, { projection: { voterId: 1, name: 1 } }).sort({ voterId: 1 }).toArray();
    const done = new Set((await votes.find({}, { projection: { voterId: 1 } }).toArray()).map((v) => v.voterId));
    res.json({ ok: true, voters: list.map((v) => ({ id: v.voterId, name: v.name, voted: done.has(v.voterId) })) });
  }));

  // GET /api/officer/voters/add?token=...&id=...&name=...&password=...
  app.get("/api/officer/voters/add", wrap(async (req, res) => {
    if (!needOfficer(req, res)) return;
    const id = cleanId(q(req, "id")), name = q(req, "name").trim(), password = q(req, "password");
    const bad = validateAccount(id, name, password);
    if (bad) return res.status(400).json({ ok: false, message: bad });
    try {
      await voters.insertOne({ voterId: id, name, passwordHash: hashPassword(password), createdAt: new Date() });
      res.json({ ok: true, message: `Voter ${id} added.` });
    } catch (err) {
      if (err.code === 11000) return res.status(409).json({ ok: false, message: "This voter ID already exists." });
      throw err;
    }
  }));

  // GET /api/officer/voters/delete?token=...&id=...
  app.get("/api/officer/voters/delete", wrap(async (req, res) => {
    if (!needOfficer(req, res)) return;
    const id = cleanId(q(req, "id"));
    const r = await voters.deleteOne({ voterId: id });
    if (!r.deletedCount) return res.status(404).json({ ok: false, message: "Voter not found." });
    for (const [t, s] of sessions) if (s.role === "voter" && s.id === id) sessions.delete(t);
    res.json({ ok: true, message: `Voter ${id} deleted.` });
  }));

  app.listen(PORT, () => console.log(`Open http://localhost:${PORT}`));
})().catch((e) => {
  console.error("Failed to start:", e.message);
  process.exit(1);
});
