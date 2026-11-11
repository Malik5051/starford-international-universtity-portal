'use strict';
/* =====================================================================
   Starford International University - Student Portal server
   No installs needed: just Node.js 18 or newer.   Start with:  node server.js
   Keep this file and index.html in the same folder. Data is saved in ./data
   ===================================================================== */
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

if (Number(process.versions.node.split('.')[0]) < 18) {
  console.error('This portal needs Node.js 18 or newer. Download the LTS version from https://nodejs.org');
  process.exit(1);
}

/* ---------- settings ---------- */
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';           // 0.0.0.0 = other computers on the network can connect too
const ROOT = __dirname;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const DB_FILE = path.join(DATA_DIR, 'db.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const PDF_DIR = path.join(DATA_DIR, 'uploads', 'transcripts');
const PHOTO_DIR = path.join(DATA_DIR, 'uploads', 'photos');
const SESSION_MS = 12 * 60 * 60 * 1000;                // stay signed in for up to 12 hours
const LIMIT = { json: 100 * 1024, pdf: 5 * 1024 * 1024, photo: 2 * 1024 * 1024 };
const TRUST_PROXY = process.env.TRUST_PROXY === '1';   // set to 1 only when running behind a reverse proxy
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1'; // set to 1 when the site is served over https

/* ---------- small helpers ---------- */
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const bad = m => new HttpError(400, m);
const uid = p => p + crypto.randomBytes(6).toString('hex');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const round2 = n => Math.round(n * 100) / 100;

function str(v, max, label, required) {
  if (v === undefined || v === null) v = '';
  if (typeof v !== 'string') throw bad(label + ' must be text.');
  v = v.trim().replace(/\s+/g, ' ');
  if (/[\u0000-\u001f\u007f]/.test(v)) throw bad(label + ' has invalid characters.');
  if (required && !v) throw bad(label + ' is required.');
  if (v.length > max) throw bad(label + ' is too long.');
  return v;
}
function cleanLoginId(v) {
  v = str(v, 30, 'ID', true);
  if (!/^[A-Za-z0-9._\/-]{3,30}$/.test(v)) throw bad('ID may use letters, numbers and . _ - / only (3 to 30 characters).');
  return v;
}
function cleanPhone(v) {
  v = str(v, 25, 'Phone number');
  if (!v) return '';
  const digits = v.replace(/\D/g, '');
  if (!/^\+?[0-9][0-9 ()-]*$/.test(v) || digits.length < 7 || digits.length > 15) throw bad('Enter a valid phone number, for example +211 912 345 678.');
  return v;
}
function cleanRollNo(v, required) {
  v = str(v, 20, 'Roll number', required);
  if (!v) return '';
  if (!/^[A-Za-z0-9._\/-]{1,20}$/.test(v)) throw bad('Roll number may use letters, numbers and . _ - / only.');
  return v;
}
function cleanYear(v) {
  const n = Number(v === undefined || v === '' ? 1 : v);
  if (!Number.isInteger(n) || n < 1 || n > 8) throw bad('Year must be a whole number from 1 to 8.');
  return n;
}
function cleanMoney(v, label) {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  if (typeof n !== 'number' || !Number.isFinite(n)) throw bad(label + ' must be a number.');
  if (n < 0 || n > 1e9) throw bad(label + ' must be between 0 and 1,000,000,000.');
  return round2(n);
}
function checkPassword(pw, loginId) {
  if (typeof pw !== 'string' || pw.length < 8) throw bad('Password must be at least 8 characters.');
  if (pw.length > 100) throw bad('Password is too long.');
  if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) throw bad('Password must contain at least one letter and one number.');
  if (loginId && pw.toLowerCase() === String(loginId).toLowerCase()) throw bad('Password must not be the same as your ID.');
}
function tempPassword() {
  const all = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  for (;;) {
    let p = '';
    for (let i = 0; i < 8; i++) p += all[crypto.randomInt(all.length)];
    if (/[A-Za-z]/.test(p) && /[0-9]/.test(p)) return p;
  }
}
const safeName = s => String(s).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'file';

/* ---------- passwords (scrypt, salted) ---------- */
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + key.toString('hex');
}
async function verifyPassword(pw, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const expected = Buffer.from(parts[2], 'hex');
  const key = await scrypt(pw, Buffer.from(parts[1], 'hex'), expected.length);
  return crypto.timingSafeEqual(key, expected);
}
let DUMMY_HASH = null;   // used so unknown IDs take as long as real ones (no user guessing by timing)

/* ---------- database (one JSON file, written safely) ---------- */
let db;
function seed() {
  return {
    settings: { currency: 'USD' },
    departments: [
      { id: 'D1', name: 'Computer Science and Information Technology' },
      { id: 'D2', name: 'Economics and Social Science' },
      { id: 'D3', name: 'Law' },
      { id: 'D4', name: 'Management Science' }
    ],
    programs: [
      { id: 'P1', departmentId: 'D1', name: 'Bachelor of Information Technology', level: 'Bachelor', years: 4 },
      { id: 'P2', departmentId: 'D1', name: 'Diploma in Computer Science', level: 'Diploma', years: 2 },
      { id: 'P3', departmentId: 'D4', name: 'Bachelor of Business Administration', level: 'Bachelor', years: 4 }
    ],
    semesters: [{ id: 'S1', name: '2026/27 Semester 1', active: true }],
    users: [], fees: [], transcripts: [], notifications: [], announcements: [], courses: [], enrollments: [], results: [], audit: []
  };
}
function ensureDirs() { [DATA_DIR, BACKUP_DIR, PDF_DIR, PHOTO_DIR].forEach(d => fs.mkdirSync(d, { recursive: true })); }
/* ---------- storage: SQLite (one file, no install) with the old db.json as an automatic fallback ---------- */
let sqlite = null;                       // the open SQLite database, or null when this Node cannot do SQLite
const SQLITE_FILE = path.join(DATA_DIR, 'portal.sqlite');
const saved = new Map();                 // what is already stored, so only changed rows are written
function openSqlite() {
  if (process.env.PORTAL_STORAGE === 'json') return null;       // escape hatch: set PORTAL_STORAGE=json to use the simple data file
  let DatabaseSync;
  try {
    const orig = process.emitWarning;
    process.emitWarning = function (w) { if (String(w && w.message || w).includes('SQLite')) return; return orig.apply(process, arguments); };
    try { ({ DatabaseSync } = require('node:sqlite')); } finally { process.emitWarning = orig; }
  } catch (e) { return null; }                                   // this Node.js has no SQLite: the simple data file is used
  const d = new DatabaseSync(SQLITE_FILE);                       // a failure here is reported by loadDb
  d.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; CREATE TABLE IF NOT EXISTS rows (coll TEXT NOT NULL, id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (coll, id));');
  return d;
}
/* every list whose items all have an id is stored one row per item; anything else is stored as one row */
function splitDb(obj) {
  const out = new Map();
  Object.keys(obj).forEach(k => {
    const v = obj[k];
    if (Array.isArray(v) && v.every(x => x && typeof x.id === 'string')) v.forEach(x => out.set(k + '\u0001' + x.id, JSON.stringify(x)));
    else out.set(k + '\u0001*', JSON.stringify(v));
    if (Array.isArray(v) && v.every(x => x && typeof x.id === 'string')) out.set(k + '\u0001#list', '1');
  });
  return out;
}
function saveDb() {
  if (!sqlite) {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
    return;
  }
  const now = splitDb(db);
  const up = sqlite.prepare('INSERT INTO rows (coll, id, json) VALUES (?, ?, ?) ON CONFLICT(coll, id) DO UPDATE SET json = excluded.json');
  const del = sqlite.prepare('DELETE FROM rows WHERE coll = ? AND id = ?');
  sqlite.exec('BEGIN');
  try {
    now.forEach((json, key) => { if (saved.get(key) !== json) { const [c, i] = key.split('\u0001'); up.run(c, i, json); } });
    saved.forEach((json, key) => { if (!now.has(key)) { const [c, i] = key.split('\u0001'); del.run(c, i); } });
    sqlite.exec('COMMIT');
  } catch (e) { try { sqlite.exec('ROLLBACK'); } catch (x) { /* nothing to undo */ } throw e; }
  saved.clear(); now.forEach((v, k) => saved.set(k, v));
}
function readSqlite() {
  const rows = sqlite.prepare('SELECT coll, id, json FROM rows ORDER BY rowid').all();
  if (!rows.length) return null;
  const obj = {};
  rows.forEach(r => {
    if (r.id === '*') obj[r.coll] = JSON.parse(r.json);
    else if (r.id === '#list') { if (!obj[r.coll]) obj[r.coll] = []; }
  });
  rows.forEach(r => { if (r.id !== '*' && r.id !== '#list') { (obj[r.coll] = obj[r.coll] || []).push(JSON.parse(r.json)); } });
  return obj;
}
function loadDb() {
  ensureDirs();
  let openError = null;
  try { sqlite = openSqlite(); } catch (e) { sqlite = null; openError = e; }
  if (sqlite || openError) {
    try {
      if (openError) throw openError;
      let data = readSqlite();
      if (data) { db = data; fillDefaults(); saveDb(); return; }
      if (fs.existsSync(DB_FILE)) {                          // first start after the upgrade: bring the old data across
        db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        fs.copyFileSync(DB_FILE, path.join(BACKUP_DIR, 'db-before-sqlite.json'));
        fillDefaults(); saveDb(); fs.renameSync(DB_FILE, DB_FILE + '.moved');
        console.log('Your existing data was moved into the new SQLite database. Your old file was kept in the backups folder.');
        return;
      }
      db = seed(); saveDb(); return;
    } catch (e) {
      console.error('SQLite problem: ' + (e && e.message));
      try { if (sqlite) sqlite.close(); } catch (x) { /* ignore */ }
      sqlite = null; saved.clear();
      if (!fs.existsSync(DB_FILE)) {
        console.error('The database file could not be read: ' + SQLITE_FILE);
        console.error('A copy from an earlier day may be in ' + BACKUP_DIR);
        process.exit(1);
      }
      console.error('Using the simple data file instead (' + DB_FILE + ').');
    }
  } else {
    console.log('Note: SQLite is not available on this Node.js (or switched off), so the simple data file is used. Node.js 22 or newer enables SQLite.');
  }
  if (!fs.existsSync(DB_FILE)) { db = seed(); saveDb(); return; }
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) {
    console.error('The data file is damaged: ' + DB_FILE);
    console.error('A copy from an earlier day may be in ' + BACKUP_DIR);
    process.exit(1);
  }
  fillDefaults();
}
function fillDefaults() {
  const s = seed();
  Object.keys(s).forEach(k => { if (db[k] === undefined) db[k] = s[k]; });
  db.settings = Object.assign({ currency: 'USD' }, db.settings);
}
/* Backups: a dated copy inside data/backups, plus (if BACKUP_COPY_DIR is set) a second copy of the database AND the uploaded files in another place, such as a USB drive */
const BACKUP_COPY_DIR = process.env.BACKUP_COPY_DIR ? path.resolve(process.env.BACKUP_COPY_DIR) : '';
function copyNewFiles(from, to) {
  if (!fs.existsSync(from)) return;
  fs.mkdirSync(to, { recursive: true });
  fs.readdirSync(from).forEach(n => { const f = path.join(to, n); if (!fs.existsSync(f)) fs.copyFileSync(path.join(from, n), f); });
}
function dailyBackup() {
  try {
    const day = new Date().toISOString().slice(0, 10), ext = sqlite ? 'sqlite' : 'json';
    const f = path.join(BACKUP_DIR, 'db-' + day + '.' + ext);
    if (!fs.existsSync(f)) {
      if (sqlite) sqlite.exec("VACUUM INTO '" + f.replace(/'/g, "''") + "'");
      else if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, f);
    }
    const all = fs.readdirSync(BACKUP_DIR).filter(n => /^db-\d{4}-\d{2}-\d{2}\.(json|sqlite)$/.test(n)).sort();
    while (all.length > 30) fs.unlinkSync(path.join(BACKUP_DIR, all.shift()));
  } catch (e) { console.error('Backup problem:', e.message); }
  if (BACKUP_COPY_DIR) {
    try {
      fs.mkdirSync(BACKUP_COPY_DIR, { recursive: true });
      const latest = path.join(BACKUP_COPY_DIR, sqlite ? 'portal-latest.sqlite' : 'db-latest.json'), tmp = latest + '.tmp';
      fs.rmSync(tmp, { force: true });
      if (sqlite) sqlite.exec("VACUUM INTO '" + tmp.replace(/'/g, "''") + "'"); else fs.copyFileSync(DB_FILE, tmp);
      fs.renameSync(tmp, latest);
      copyNewFiles(PDF_DIR, path.join(BACKUP_COPY_DIR, 'uploads', 'transcripts'));
      copyNewFiles(PHOTO_DIR, path.join(BACKUP_COPY_DIR, 'uploads', 'photos'));
    } catch (e) { console.error('Could not write the second backup copy to ' + BACKUP_COPY_DIR + ': ' + e.message); }
  }
}
function audit(user, action, detail) {
  db.audit.push({ at: Date.now(), by: user ? user.id : '', byName: user ? user.name : 'system', action, detail });
  if (db.audit.length > 2000) db.audit.splice(0, db.audit.length - 2000);
}
function notify(userId, text) {
  db.notifications.push({ id: uid('N'), userId, text, at: Date.now(), read: false });
  const mine = db.notifications.filter(n => n.userId === userId);
  if (mine.length > 200) {
    const drop = new Set(mine.sort((a, b) => a.at - b.at).slice(0, mine.length - 200).map(n => n.id));
    db.notifications = db.notifications.filter(n => !drop.has(n.id));
  }
}

/* ---------- sessions: many people can be signed in at the same time ---------- */
const sessions = new Map();   // sha256(token) -> { userId, exp }
let sessTimer = null;
function loadSessions() {
  try {
    const raw = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
    Object.keys(raw).forEach(h => { if (raw[h].exp > Date.now()) sessions.set(h, raw[h]); });
  } catch (e) { /* no sessions yet */ }
}
function writeSessions() {
  try {
    const obj = {};
    sessions.forEach((v, k) => { if (v.exp > Date.now()) obj[k] = v; });
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(obj));
  } catch (e) { console.error('Could not save sessions:', e.message); }
}
function saveSessions() { clearTimeout(sessTimer); sessTimer = setTimeout(writeSessions, 200); }
function killSessions(userId, exceptHash) {
  sessions.forEach((v, k) => { if (v.userId === userId && k !== exceptHash) sessions.delete(k); });
  saveSessions();
}
function cookieOf(req) {
  const name = req.slot ? 'sid_' + req.slot : 'sid';     // every browser tab has its own slot, so tabs can hold different logins
  const m = new RegExp('(?:^|;\\s*)' + name + '=([A-Za-z0-9_-]{20,100})').exec(req.headers.cookie || '');
  return m ? m[1] : null;
}
function authenticate(req) {
  const token = cookieOf(req);
  if (!token) return null;
  const hash = sha(token), s = sessions.get(hash);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(hash); return null; }
  const user = db.users.find(u => u.id === s.userId);
  if (!user || user.active === false) return null;
  if (s.exp - Date.now() < SESSION_MS / 2) { s.exp = Date.now() + SESSION_MS; saveSessions(); }   // keep active people signed in
  return { user, hash };
}
function setCookie(res, token, maxAgeSec) {
  const slot = res.slot;
  res.setHeader('Set-Cookie', (slot ? 'sid_' + slot : 'sid') + '=' + token + '; HttpOnly; SameSite=Strict; Path=' + (slot ? '/s/' + slot : '/') + '; Max-Age=' + maxAgeSec + (COOKIE_SECURE ? '; Secure' : ''));
}

/* ---------- slow down password guessing ---------- */
const fails = new Map();
function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || '';
}
function limitCheck(keys) {
  keys.forEach(k => { const f = fails.get(k.key); if (f && f.until > Date.now()) throw new HttpError(429, 'Too many failed attempts. Please wait a few minutes and try again.'); });
}
function limitFail(keys) {
  keys.forEach(k => {
    const f = fails.get(k.key) || { n: 0, until: 0 };
    f.n++;
    if (f.n >= k.max) { f.until = Date.now() + 5 * 60 * 1000; f.n = 0; }
    fails.set(k.key, f);
  });
  if (fails.size > 20000) fails.clear();
}

/* ---------- request helpers ---------- */
function send(res, status, obj) {
  const body = JSON.stringify(obj === undefined ? {} : obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0, tooBig = Number(req.headers['content-length'] || 0) > limit, done = false;
    const chunks = [];
    const finish = (fn, v) => { if (!done) { done = true; fn(v); } };
    req.on('data', ch => {
      size += ch.length;
      if (size > limit) tooBig = true;
      if (size > 64 * 1024 * 1024) { req.destroy(); return; }
      if (!tooBig) chunks.push(ch);
    });
    req.on('end', () => finish(tooBig ? reject : resolve, tooBig ? new HttpError(413, 'That file or request is too large.') : Buffer.concat(chunks)));
    req.on('error', e => finish(reject, e));
    req.on('close', () => finish(reject, new HttpError(400, 'Upload was interrupted.')));
  });
}
async function readJson(req, limit) {
  const buf = await readBody(req, limit || LIMIT.json);
  if (!buf.length) return {};
  try {
    const v = JSON.parse(buf.toString('utf8'));
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('shape');
    return v;
  } catch (e) { throw bad('Invalid request.'); }
}

/* ---------- views of records ---------- */
const pub = u => ({
  id: u.id, loginId: u.loginId, name: u.name, role: u.role, phone: u.phone || '',
  departmentId: u.departmentId || '', programId: u.programId || '', year: u.year || null, rollNo: u.rollNo || '',
  active: u.active !== false, mustChange: !!u.mustChange,
  hasPhoto: !!u.photo, photoV: u.photo ? u.photo.v : 0, createdAt: u.createdAt || 0
});
const findByLogin = id => db.users.find(u => u.loginId.toLowerCase() === String(id).toLowerCase());
const userById = id => db.users.find(u => u.id === id);
const studentById = id => { const u = userById(id); return u && u.role === 'student' ? u : null; };
const semById = id => db.semesters.find(s => s.id === id);
const feeOf = (sid, semId) => db.fees.find(f => f.studentId === sid && f.semesterId === semId);
const feeView = f => f ? { total: f.total, paid: f.paid, balance: round2(f.total - f.paid), updatedAt: f.updatedAt } : null;
const money = n => db.settings.currency + ' ' + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const trView = t => t ? { id: t.id, originalName: t.originalName, size: t.size, uploadedAt: t.uploadedAt } : null;
function filterStudents(q) {
  const text = String(q.q || '').toLowerCase();
  return db.users.filter(u => u.role === 'student' &&
      (!q.departmentId || u.departmentId === q.departmentId) &&
      (!q.programId || u.programId === q.programId) &&
      (!text || u.name.toLowerCase().includes(text) || u.loginId.toLowerCase().includes(text) || (u.rollNo || '').toLowerCase().includes(text)))
    .sort((a, b) => a.name.localeCompare(b.name)).slice(0, 2000);
}
function removeFile(p) { try { fs.unlinkSync(p); } catch (e) { /* already gone */ } }
const photoPath = u => path.join(PHOTO_DIR, u.id + '.' + u.photo.ext);
const pdfPath = t => path.join(PDF_DIR, t.file);

/* ---------- router ---------- */
const routes = [];
function route(method, pattern, auth, handler) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:([A-Za-z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, auth, handler });
}
const MUST_CHANGE_OK = new Set(['/api/me', '/api/password', '/api/logout']);

async function handleApi(req, res, url) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.method !== 'HEAD') {          // protection against other websites sending requests for a signed-in user
    if (req.headers['x-portal'] !== '1') throw new HttpError(403, 'Blocked request.');
    if (req.headers.origin) {
      let host = '';
      try { host = new URL(req.headers.origin).host; } catch (e) { /* invalid */ }
      if (host !== req.headers.host) throw new HttpError(403, 'Blocked request.');
    }
  }
  let match = null, pathExists = false;
  for (const r of routes) {
    const m = r.re.exec(url.pathname);
    if (!m) continue;
    if (r.method !== req.method) { pathExists = true; continue; }
    match = { r, m }; break;
  }
  if (!match) throw new HttpError(pathExists ? 405 : 404, pathExists ? 'Method not allowed.' : 'Not found.');
  const c = { req, res, url, query: Object.fromEntries(url.searchParams), params: {}, user: null, hash: null };
  match.r.keys.forEach((k, i) => { try { c.params[k] = decodeURIComponent(match.m[i + 1]); } catch (e) { c.params[k] = ''; } });
  if (match.r.auth !== 'public') {
    const a = authenticate(req);
    if (!a) throw new HttpError(401, 'Please sign in.');
    c.user = a.user; c.hash = a.hash;
    if (c.user.mustChange && !MUST_CHANGE_OK.has(url.pathname)) { const e = new HttpError(403, 'Please change your temporary password first.'); e.code = 'MUST_CHANGE'; throw e; }
    if (Array.isArray(match.r.auth) && !match.r.auth.includes(c.user.role)) throw new HttpError(403, 'You do not have access to this.');
  }
  await match.r.handler(c);
}

/* ======================= ROUTES ======================= */

/* ----- sign in / out ----- */
route('POST', '/api/login', 'public', async c => {
  const b = await readJson(c.req);
  const loginId = typeof b.loginId === 'string' ? b.loginId.trim().slice(0, 40) : '';
  const password = typeof b.password === 'string' ? b.password.slice(0, 200) : '';
  if (!loginId || !password) throw bad('Enter your ID and password.');
  const keys = [{ key: clientIp(c.req) + '|' + loginId.toLowerCase(), max: 5 }, { key: 'ip|' + clientIp(c.req), max: 40 }];
  limitCheck(keys);
  const user = findByLogin(loginId);
  const ok = await verifyPassword(password, user ? user.passHash : DUMMY_HASH);
  if (!user || !ok || user.active === false) {
    limitFail(keys);
    throw new HttpError(401, user && ok && user.active === false ? 'This account has been deactivated. Contact the registry.' : 'Wrong ID or password.');
  }
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(sha(token), { userId: user.id, exp: Date.now() + SESSION_MS });
  saveSessions();
  setCookie(c.res, token, SESSION_MS / 1000);
  send(c.res, 200, { user: pub(user) });
});
route('POST', '/api/logout', 'public', c => {
  const token = cookieOf(c.req);
  if (token) { sessions.delete(sha(token)); saveSessions(); }
  setCookie(c.res, '', 0);
  send(c.res, 200, { ok: true });
});
route('GET', '/api/me', 'any', c => send(c.res, 200, { user: pub(c.user) }));
route('POST', '/api/password', 'any', async c => {
  const b = await readJson(c.req);
  if (!(await verifyPassword(String(b.current || ''), c.user.passHash))) throw bad('Your current password is not correct.');
  checkPassword(b.next, c.user.loginId);
  if (b.next === b.current) throw bad('Choose a new password that is different from the old one.');
  c.user.passHash = await hashPassword(b.next);
  c.user.mustChange = false;
  killSessions(c.user.id, c.hash);                    // sign out this person on all other devices
  audit(c.user, 'password', 'Password changed');
  saveDb();
  send(c.res, 200, { user: pub(c.user) });
});

/* ----- own profile: phone and photo ----- */
route('PUT', '/api/me', 'any', async c => {
  const b = await readJson(c.req);
  c.user.phone = cleanPhone(b.phone);
  saveDb();
  send(c.res, 200, { user: pub(c.user) });
});
function imageType(buf) {
  if (buf.length > 3 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'jpg';
  if (buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'png';
  return null;
}
async function storePhoto(c, target) {
  const buf = await readBody(c.req, LIMIT.photo);
  const ext = imageType(buf);
  if (!ext) throw bad('Please choose a JPG or PNG photo.');
  if (target.photo) removeFile(photoPath(target));
  fs.writeFileSync(path.join(PHOTO_DIR, target.id + '.' + ext), buf);
  target.photo = { ext, v: Date.now() };
  saveDb();
  send(c.res, 200, { user: pub(target) });
}
function dropPhoto(c, target) {
  if (target.photo) { removeFile(photoPath(target)); target.photo = null; saveDb(); }
  send(c.res, 200, { user: pub(target) });
}
route('PUT', '/api/me/photo', 'any', c => storePhoto(c, c.user));
route('DELETE', '/api/me/photo', 'any', c => dropPhoto(c, c.user));
route('PUT', '/api/users/:id/photo', ['admin'], c => { const u = userById(c.params.id); if (!u) throw new HttpError(404, 'Person not found.'); return storePhoto(c, u); });
route('DELETE', '/api/users/:id/photo', ['admin'], c => { const u = userById(c.params.id); if (!u) throw new HttpError(404, 'Person not found.'); dropPhoto(c, u); });
route('GET', '/api/users/:id/photo', 'any', c => {
  const u = userById(c.params.id);
  if (!u || !u.photo) throw new HttpError(404, 'No photo.');
  if (c.user.id !== u.id && c.user.role === 'student') throw new HttpError(403, 'You do not have access to this.');
  fs.readFile(photoPath(u), (err, data) => {
    if (err) return send(c.res, 404, { error: 'No photo.' });
    c.res.writeHead(200, { 'Content-Type': u.photo.ext === 'png' ? 'image/png' : 'image/jpeg', 'Content-Length': data.length, 'Cache-Control': 'private, max-age=86400' });
    c.res.end(data);
  });
});

/* ----- reference data everyone can read ----- */
route('GET', '/api/meta', 'any', c => send(c.res, 200, {
  departments: db.departments, programs: db.programs, semesters: db.semesters, settings: db.settings
}));

/* ----- departments ----- */
route('POST', '/api/departments', ['admin'], async c => {
  const b = await readJson(c.req);
  const name = str(b.name, 100, 'Department name', true);
  if (db.departments.some(d => d.name.toLowerCase() === name.toLowerCase())) throw bad('That department already exists.');
  const d = { id: uid('D'), name };
  db.departments.push(d); audit(c.user, 'department', 'Added ' + name); saveDb();
  send(c.res, 201, d);
});
route('PUT', '/api/departments/:id', ['admin'], async c => {
  const d = db.departments.find(x => x.id === c.params.id);
  if (!d) throw new HttpError(404, 'Department not found.');
  const name = str((await readJson(c.req)).name, 100, 'Department name', true);
  if (db.departments.some(x => x.id !== d.id && x.name.toLowerCase() === name.toLowerCase())) throw bad('That department already exists.');
  d.name = name; saveDb();
  send(c.res, 200, d);
});
route('DELETE', '/api/departments/:id', ['admin'], c => {
  const d = db.departments.find(x => x.id === c.params.id);
  if (!d) throw new HttpError(404, 'Department not found.');
  if (db.programs.some(p => p.departmentId === d.id)) throw bad('Delete or move the programs in this department first.');
  if (db.users.some(u => u.departmentId === d.id)) throw bad('People are still assigned to this department.');
  if (db.courses.some(co => co.departmentId === d.id)) throw bad('Courses still belong to this department.');
  db.departments = db.departments.filter(x => x.id !== d.id); audit(c.user, 'department', 'Deleted ' + d.name); saveDb();
  send(c.res, 200, { ok: true });
});

/* ----- programs ----- */
function cleanProgram(b) {
  const department = db.departments.find(d => d.id === b.departmentId);
  if (!department) throw bad('Choose a department.');
  const level = ['Diploma', 'Bachelor', 'Master', 'PhD'].includes(b.level) ? b.level : null;
  if (!level) throw bad('Choose a level.');
  const years = Number(b.years);
  if (!Number.isInteger(years) || years < 1 || years > 8) throw bad('Years must be from 1 to 8.');
  return { departmentId: department.id, name: str(b.name, 120, 'Program name', true), level, years };
}
route('POST', '/api/programs', ['admin'], async c => {
  const p = Object.assign({ id: uid('P') }, cleanProgram(await readJson(c.req)));
  db.programs.push(p); audit(c.user, 'program', 'Added ' + p.name); saveDb();
  send(c.res, 201, p);
});
route('PUT', '/api/programs/:id', ['admin'], async c => {
  const p = db.programs.find(x => x.id === c.params.id);
  if (!p) throw new HttpError(404, 'Program not found.');
  const next = cleanProgram(Object.assign({}, p, await readJson(c.req)));
  Object.assign(p, next);
  db.users.forEach(u => { if (u.role === 'student' && u.programId === p.id) u.departmentId = p.departmentId; });   // keep students in the right department
  saveDb();
  send(c.res, 200, p);
});
route('DELETE', '/api/programs/:id', ['admin'], c => {
  const p = db.programs.find(x => x.id === c.params.id);
  if (!p) throw new HttpError(404, 'Program not found.');
  if (db.users.some(u => u.programId === p.id)) throw bad('Students are still registered in this program.');
  if (db.courses.some(co => co.programId === p.id)) throw bad('Courses still belong to this program.');
  db.programs = db.programs.filter(x => x.id !== p.id); audit(c.user, 'program', 'Deleted ' + p.name); saveDb();
  send(c.res, 200, { ok: true });
});

/* ----- semesters ----- */
route('POST', '/api/semesters', ['admin'], async c => {
  const name = str((await readJson(c.req)).name, 60, 'Semester name', true);
  if (db.semesters.some(s => s.name.toLowerCase() === name.toLowerCase())) throw bad('That semester already exists.');
  const s = { id: uid('S'), name, active: db.semesters.length === 0 };
  db.semesters.push(s); saveDb();
  send(c.res, 201, s);
});
route('POST', '/api/semesters/:id/activate', ['admin'], c => {
  const s = semById(c.params.id);
  if (!s) throw new HttpError(404, 'Semester not found.');
  db.semesters.forEach(x => { x.active = x.id === s.id; }); saveDb();
  send(c.res, 200, { ok: true });
});
route('PUT', '/api/semesters/:id/registration', ['admin'], async c => {
  const sm = semById(c.params.id);
  if (!sm) throw new HttpError(404, 'Semester not found.');
  const b = await readJson(c.req);
  if (b.regOpen !== undefined) sm.regOpen = b.regOpen === true;
  if (b.maxCredits !== undefined) {
    const n = Number(b.maxCredits);
    if (!Number.isFinite(n) || n < 1 || n > 60) throw bad('Maximum credits must be a number from 1 to 60.');
    sm.maxCredits = n;
  }
  audit(c.user, 'semester', 'Registration for ' + sm.name + ' is ' + (sm.regOpen === false ? 'closed' : 'open') + ', max credits ' + (sm.maxCredits || 24)); saveDb();
  send(c.res, 200, sm);
});
route('DELETE', '/api/semesters/:id', ['admin'], c => {
  const s = semById(c.params.id);
  if (!s) throw new HttpError(404, 'Semester not found.');
  if (db.fees.some(f => f.semesterId === s.id) || db.transcripts.some(t => t.semesterId === s.id) || db.enrollments.some(e => e.semesterId === s.id)) throw bad('This semester has fees, transcripts or enrolments and cannot be deleted.');
  db.semesters = db.semesters.filter(x => x.id !== s.id); saveDb();
  send(c.res, 200, { ok: true });
});

/* ----- settings ----- */
route('PUT', '/api/settings', ['admin'], async c => {
  const b = await readJson(c.req);
  if (b.currency !== undefined) {
    const cur = str(b.currency, 6, 'Currency', true).toUpperCase();
    if (!/^[A-Z]{2,6}$/.test(cur)) throw bad('Currency should be letters only, for example USD or SSP.');
    db.settings.currency = cur;
  }
  if (b.blockPickIfOwing !== undefined) db.settings.blockPickIfOwing = b.blockPickIfOwing === true;
  audit(c.user, 'settings', 'Settings changed'); saveDb();
  send(c.res, 200, db.settings);
});

/* ----- people (students, lecturers, admins) ----- */
route('GET', '/api/users', ['admin'], c => {
  const role = ['student', 'lecturer', 'admin', 'accounts'].includes(c.query.role) ? c.query.role : '';
  let list;
  if (role === 'lecturer') {
    const text = String(c.query.q || '').toLowerCase();
    list = db.users.filter(u => u.role === 'lecturer' && (!c.query.departmentId || u.departmentId === c.query.departmentId) &&
      (!text || u.name.toLowerCase().includes(text) || u.loginId.toLowerCase().includes(text))).sort((a, b) => a.name.localeCompare(b.name));
  } else if (role === 'student' || !role) {
    list = filterStudents(c.query);
    if (!role) list = list.concat(db.users.filter(u => u.role !== 'student'));
  } else {
    list = db.users.filter(u => u.role === role).sort((a, b) => a.name.localeCompare(b.name));
  }
  send(c.res, 200, { users: list.map(pub) });
});
route('POST', '/api/users', ['admin'], async c => {
  const b = await readJson(c.req);
  if (!['student', 'lecturer', 'admin', 'accounts'].includes(b.role)) throw bad('Choose a role.');
  const u = { id: uid('U'), role: b.role, name: str(b.name, 80, 'Name', true), loginId: cleanLoginId(b.loginId), phone: cleanPhone(b.phone), active: true, mustChange: true, createdAt: Date.now() };
  if (findByLogin(u.loginId)) throw bad('That ID is already used by someone else.');
  if (u.role === 'student') {
    const p = db.programs.find(x => x.id === b.programId);
    if (!p) throw bad('Choose a program.');
    u.programId = p.id; u.departmentId = p.departmentId; u.year = cleanYear(b.year);
    u.rollNo = cleanRollNo(b.rollNo, true);
    if (db.users.some(x => x.role === 'student' && (x.rollNo || '').toLowerCase() === u.rollNo.toLowerCase())) throw bad('That roll number is already used by another student.');
  } else if (b.departmentId) {
    if (!db.departments.some(d => d.id === b.departmentId)) throw bad('Department not found.');
    u.departmentId = b.departmentId;
  } else if (u.role === 'lecturer') {
    throw bad('Choose the lecturer\'s department. Lecturers pick their courses from their own department.');
  }
  let pw = typeof b.password === 'string' && b.password ? b.password : '';
  if (pw) checkPassword(pw, u.loginId); else pw = tempPassword();
  u.passHash = await hashPassword(pw);
  if (findByLogin(u.loginId)) throw bad('That ID is already used by someone else.');   // checked again: another admin may have added it meanwhile
  db.users.push(u); audit(c.user, 'user', 'Added ' + u.role + ' ' + u.loginId); saveDb();
  send(c.res, 201, { user: pub(u), tempPassword: pw });
});
const activeAdmins = () => db.users.filter(u => u.role === 'admin' && u.active !== false);
route('PUT', '/api/users/:id', ['admin'], async c => {
  const u = userById(c.params.id);
  if (!u) throw new HttpError(404, 'Person not found.');
  const b = await readJson(c.req), patch = {};
  if (b.name !== undefined) patch.name = str(b.name, 80, 'Name', true);
  if (b.loginId !== undefined && b.loginId !== u.loginId) {
    patch.loginId = cleanLoginId(b.loginId);
    const other = findByLogin(patch.loginId);
    if (other && other.id !== u.id) throw bad('That ID is already used by someone else.');
  }
  if (b.phone !== undefined) patch.phone = cleanPhone(b.phone);
  if (u.role === 'student') {
    if (b.programId !== undefined) {
      const p = db.programs.find(x => x.id === b.programId);
      if (!p) throw bad('Choose a program.');
      patch.programId = p.id; patch.departmentId = p.departmentId;
    }
    if (b.year !== undefined) patch.year = cleanYear(b.year);
    if (b.rollNo !== undefined) {
      patch.rollNo = cleanRollNo(b.rollNo, false);
      if (patch.rollNo && db.users.some(x => x.id !== u.id && x.role === 'student' && (x.rollNo || '').toLowerCase() === patch.rollNo.toLowerCase())) throw bad('That roll number is already used by another student.');
    }
  }
  if (b.active !== undefined) {
    if (typeof b.active !== 'boolean') throw bad('Invalid status.');
    if (!b.active && u.id === c.user.id) throw bad('You cannot deactivate your own account.');
    if (!b.active && u.role === 'admin' && activeAdmins().length <= 1) throw bad('There must be at least one active administrator.');
    patch.active = b.active;
  }
  Object.assign(u, patch);
  if (patch.active === false) killSessions(u.id);
  audit(c.user, 'user', 'Edited ' + u.loginId); saveDb();
  send(c.res, 200, { user: pub(u) });
});
route('POST', '/api/users/:id/reset-password', ['admin'], async c => {
  const u = userById(c.params.id);
  if (!u) throw new HttpError(404, 'Person not found.');
  const pw = tempPassword();
  u.passHash = await hashPassword(pw); u.mustChange = true;
  killSessions(u.id);
  audit(c.user, 'user', 'Reset password for ' + u.loginId); saveDb();
  send(c.res, 200, { tempPassword: pw });
});
route('DELETE', '/api/users/:id', ['admin'], c => {
  const u = userById(c.params.id);
  if (!u) throw new HttpError(404, 'Person not found.');
  if (u.id === c.user.id) throw bad('You cannot delete your own account.');
  if (u.role === 'admin' && u.active !== false && activeAdmins().length <= 1) throw bad('There must be at least one active administrator.');
  if (u.photo) removeFile(photoPath(u));
  db.transcripts.filter(t => t.studentId === u.id).forEach(t => removeFile(pdfPath(t)));
  db.transcripts = db.transcripts.filter(t => t.studentId !== u.id);
  db.fees = db.fees.filter(f => f.studentId !== u.id);
  db.enrollments = db.enrollments.filter(e => e.studentId !== u.id);
  db.results = db.results.filter(r => r.studentId !== u.id);
  db.courses.forEach(co => { if (co.lecturerId === u.id) co.lecturerId = ''; });
  db.notifications = db.notifications.filter(n => n.userId !== u.id);
  db.users = db.users.filter(x => x.id !== u.id);
  killSessions(u.id);
  audit(c.user, 'user', 'Deleted ' + u.role + ' ' + u.loginId); saveDb();
  send(c.res, 200, { ok: true });
});

/* ----- bulk student import: the browser reads a CSV file and sends the rows; each row is checked on its own ----- */
route('POST', '/api/users/import', ['admin'], async c => {
  const b = await readJson(c.req, 400 * 1024);
  if (!Array.isArray(b.rows) || !b.rows.length) throw bad('The list is empty.');
  if (b.rows.length > 400) throw bad('Please import at most 400 students at a time.');
  const results = [], seenLogin = new Set(), seenRoll = new Set();
  for (let i = 0; i < b.rows.length; i++) {
    const r = b.rows[i] || {};
    try {
      const prog = db.programs.find(p => p.id === r.program || p.name.toLowerCase() === String(r.program || '').trim().toLowerCase());
      if (!prog) throw bad('Program not found: ' + String(r.program || '').slice(0, 60));
      const u = { id: uid('U'), role: 'student', name: str(r.name, 80, 'Name', true), loginId: cleanLoginId(r.loginId), rollNo: cleanRollNo(r.rollNo, true), phone: cleanPhone(r.phone), programId: prog.id, departmentId: prog.departmentId, year: cleanYear(r.year), active: true, mustChange: true, createdAt: Date.now() };
      if (findByLogin(u.loginId) || seenLogin.has(u.loginId.toLowerCase())) throw bad('Registration number already used.');
      if (seenRoll.has(u.rollNo.toLowerCase()) || db.users.some(x => x.role === 'student' && (x.rollNo || '').toLowerCase() === u.rollNo.toLowerCase())) throw bad('Roll number already used.');
      const pw = tempPassword(); u.passHash = await hashPassword(pw);
      seenLogin.add(u.loginId.toLowerCase()); seenRoll.add(u.rollNo.toLowerCase());
      db.users.push(u);
      results.push({ row: i + 1, ok: true, name: u.name, loginId: u.loginId, rollNo: u.rollNo, tempPassword: pw });
    } catch (e) {
      if (!(e instanceof HttpError)) throw e;
      results.push({ row: i + 1, ok: false, name: String(r.name || '').slice(0, 80), loginId: String(r.loginId || '').slice(0, 30), error: e.message });
    }
  }
  const added = results.filter(x => x.ok).length;
  if (added) { audit(c.user, 'user', 'Imported ' + added + ' student(s) from a list'); saveDb(); }
  send(c.res, 200, { added, failed: results.length - added, results });
});
route('GET', '/api/audit', ['admin'], c => {
  const text = String(c.query.q || '').toLowerCase();
  const rows = db.audit.filter(a => !text || (a.byName + ' ' + a.action + ' ' + a.detail).toLowerCase().includes(text)).slice(-300).reverse();
  send(c.res, 200, { rows });
});

/* ----- fees: the admin enters total required and amount paid; the balance is total minus paid ----- */
route('GET', '/api/fees', ['admin', 'accounts'], c => {
  const sem = semById(c.query.semesterId);
  if (!sem) throw bad('Choose a semester.');
  send(c.res, 200, { rows: filterStudents(c.query).map(s => ({ student: pub(s), fee: feeView(feeOf(s.id, sem.id)) })) });
});
route('PUT', '/api/fees/:studentId/:semesterId', ['admin', 'accounts'], async c => {
  const stu = studentById(c.params.studentId), sem = semById(c.params.semesterId);
  if (!stu) throw new HttpError(404, 'Student not found.');
  if (!sem) throw new HttpError(404, 'Semester not found.');
  const b = await readJson(c.req);
  const total = cleanMoney(b.total, 'Total required'), paid = cleanMoney(b.paid, 'Amount paid');
  let f = feeOf(stu.id, sem.id);
  const changed = !f || f.total !== total || f.paid !== paid;
  if (!f) { f = { studentId: stu.id, semesterId: sem.id }; db.fees.push(f); }
  Object.assign(f, { total, paid, updatedAt: Date.now(), updatedBy: c.user.id });
  if (changed) {
    notify(stu.id, 'Your fees for ' + sem.name + ' were updated. Required ' + money(total) + ', paid ' + money(paid) + ', balance ' + money(round2(total - paid)) + '.');
    audit(c.user, 'fees', stu.loginId + ' ' + sem.name + ' total ' + total + ' paid ' + paid);
  }
  saveDb();
  send(c.res, 200, { fee: feeView(f) });
});
route('GET', '/api/my/fees', ['student'], c => {
  const rows = db.fees.filter(f => f.studentId === c.user.id).map(f => {
    const s = semById(f.semesterId);
    return s ? { semester: { id: s.id, name: s.name, active: s.active }, total: f.total, paid: f.paid, balance: round2(f.total - f.paid) } : null;
  }).filter(Boolean).sort((a, b) => db.semesters.findIndex(s => s.id === b.semester.id) - db.semesters.findIndex(s => s.id === a.semester.id));
  const sum = k => round2(rows.reduce((a, r) => a + r[k], 0));
  send(c.res, 200, { rows, totals: { total: sum('total'), paid: sum('paid'), balance: sum('balance') } });
});

/* ----- transcripts: the admin uploads a PDF per student per semester; the student downloads it ----- */
route('GET', '/api/transcripts', ['admin'], c => {
  const sem = semById(c.query.semesterId);
  if (!sem) throw bad('Choose a semester.');
  send(c.res, 200, {
    rows: filterStudents(c.query).map(s => ({ student: pub(s), transcript: trView(db.transcripts.find(t => t.studentId === s.id && t.semesterId === sem.id)) }))
  });
});
route('PUT', '/api/transcripts/:studentId/:semesterId', ['admin'], async c => {
  const stu = studentById(c.params.studentId), sem = semById(c.params.semesterId);
  if (!stu) throw new HttpError(404, 'Student not found.');
  if (!sem) throw new HttpError(404, 'Semester not found.');
  const buf = await readBody(c.req, LIMIT.pdf);
  if (buf.length < 8 || buf.subarray(0, 5).toString('latin1') !== '%PDF-') throw bad('Only PDF files can be uploaded as transcripts.');
  let name = String(c.query.filename || 'transcript.pdf').split(/[\\/]/).pop().replace(/[^\w .()-]/g, '').trim().slice(0, 80) || 'transcript.pdf';
  if (!/\.pdf$/i.test(name)) name += '.pdf';
  const file = uid('T') + '.pdf';
  fs.writeFileSync(path.join(PDF_DIR, file), buf);
  const old = db.transcripts.find(t => t.studentId === stu.id && t.semesterId === sem.id);
  if (old) { removeFile(pdfPath(old)); db.transcripts = db.transcripts.filter(t => t !== old); }
  const t = { id: old ? old.id : uid('TR'), studentId: stu.id, semesterId: sem.id, file, originalName: name, size: buf.length, uploadedAt: Date.now(), uploadedBy: c.user.id };
  db.transcripts.push(t);
  notify(stu.id, 'Your transcript for ' + sem.name + ' is ready. Open My Transcripts to download it.');
  audit(c.user, 'transcript', (old ? 'Replaced ' : 'Uploaded ') + stu.loginId + ' ' + sem.name);
  saveDb();
  send(c.res, 200, { transcript: trView(t) });
});
route('DELETE', '/api/transcripts/:id', ['admin'], c => {
  const t = db.transcripts.find(x => x.id === c.params.id);
  if (!t) throw new HttpError(404, 'Transcript not found.');
  removeFile(pdfPath(t));
  db.transcripts = db.transcripts.filter(x => x !== t);
  audit(c.user, 'transcript', 'Deleted transcript ' + t.id); saveDb();
  send(c.res, 200, { ok: true });
});
route('GET', '/api/my/transcripts', ['student'], c => {
  const rows = db.transcripts.filter(t => t.studentId === c.user.id).map(t => {
    const s = semById(t.semesterId);
    return Object.assign(trView(t), { semester: s ? { id: s.id, name: s.name } : { id: '', name: '(removed semester)' } });
  }).sort((a, b) => b.uploadedAt - a.uploadedAt);
  send(c.res, 200, { rows });
});
route('GET', '/api/transcripts/:id/download', 'any', c => {
  const t = db.transcripts.find(x => x.id === c.params.id);
  const allowed = t && (c.user.role === 'admin' || (c.user.role === 'student' && t.studentId === c.user.id));
  if (!allowed) throw new HttpError(t ? 403 : 404, t ? 'You do not have access to this.' : 'Transcript not found.');
  const stu = userById(t.studentId), sem = semById(t.semesterId);
  fs.readFile(pdfPath(t), (err, data) => {
    if (err) return send(c.res, 404, { error: 'The file is missing on the server.' });
    const fname = 'Transcript-' + safeName(stu ? stu.loginId : 'student') + '-' + safeName(sem ? sem.name : 'semester') + '.pdf';
    c.res.writeHead(200, { 'Content-Type': 'application/pdf', 'Content-Length': data.length, 'Content-Disposition': 'attachment; filename="' + fname + '"', 'Cache-Control': 'private, no-store' });
    c.res.end(data);
  });
});

/* ----- notifications ----- */
route('GET', '/api/notifications', 'any', c => {
  const mine = db.notifications.filter(n => n.userId === c.user.id).sort((a, b) => b.at - a.at).slice(0, 50);
  send(c.res, 200, { notifications: mine.map(n => ({ id: n.id, text: n.text, at: n.at, read: n.read })), unread: mine.filter(n => !n.read).length });
});
route('GET', '/api/notifications/count', 'any', c => send(c.res, 200, { unread: db.notifications.filter(n => n.userId === c.user.id && !n.read).length }));
route('POST', '/api/notifications/read', 'any', c => {
  db.notifications.forEach(n => { if (n.userId === c.user.id) n.read = true; });
  saveDb();
  send(c.res, 200, { ok: true });
});

/* ----- announcements: the admin posts; everyone reads what is meant for their group ----- */
const AUDIENCES = ['all', 'student', 'lecturer'];
const LECTURER_AUDIENCES = ['student', 'lecturer'];      // lecturers can write to students or to colleagues, not to everyone
const annForUser = u => db.announcements.filter(a => u.role === 'admin' || a.by === u.id || a.audience === 'all' || a.audience === u.role)
  .sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || b.at - a.at);
const annIsNew = (a, u) => u.role !== 'admin' && a.by !== u.id && a.at > (u.annSeen || 0);
const annView = (a, u) => ({ id: a.id, title: a.title, body: a.body, audience: a.audience, at: a.at, by: a.byName, byRole: a.byRole || 'admin', pinned: !!a.pinned,
  mine: a.by === u.id, canDelete: u.role === 'admin' || a.by === u.id, unread: annIsNew(a, u) });
route('GET', '/api/announcements', 'any', c => {
  const list = annForUser(c.user).slice(0, 100);
  send(c.res, 200, { announcements: list.map(a => annView(a, c.user)), unread: list.filter(a => annIsNew(a, c.user)).length });
});
route('GET', '/api/announcements/count', 'any', c => send(c.res, 200, { unread: annForUser(c.user).filter(a => annIsNew(a, c.user)).length }));
route('POST', '/api/announcements/seen', 'any', c => { c.user.annSeen = Date.now(); saveDb(); send(c.res, 200, { ok: true }); });
route('POST', '/api/announcements', ['admin', 'lecturer'], async c => {
  const b = await readJson(c.req);
  if (!(c.user.role === 'admin' ? AUDIENCES : LECTURER_AUDIENCES).includes(b.audience)) throw bad('Choose who should see this announcement.');
  const a = { id: uid('A'), title: str(b.title, 120, 'Title', true), body: str(b.body, 3000, 'Message', true), audience: b.audience, by: c.user.id, byName: c.user.name, byRole: c.user.role, at: Date.now() };
  db.announcements.push(a);
  if (db.announcements.length > 500) db.announcements.splice(0, db.announcements.length - 500);
  audit(c.user, 'announcement', 'Posted "' + a.title + '" to ' + a.audience); saveDb();
  send(c.res, 201, { announcement: annView(a, c.user) });
});
route('POST', '/api/announcements/:id/pin', ['admin'], c => {
  const a = db.announcements.find(x => x.id === c.params.id);
  if (!a) throw new HttpError(404, 'Announcement not found.');
  a.pinned = !a.pinned; saveDb();
  send(c.res, 200, { pinned: a.pinned });
});
route('DELETE', '/api/announcements/:id', ['admin', 'lecturer'], c => {
  const a = db.announcements.find(x => x.id === c.params.id);
  if (!a) throw new HttpError(404, 'Announcement not found.');
  if (c.user.role !== 'admin' && a.by !== c.user.id) throw new HttpError(403, 'You can only delete your own announcements.');
  db.announcements = db.announcements.filter(x => x !== a);
  audit(c.user, 'announcement', 'Deleted "' + a.title + '"'); saveDb();
  send(c.res, 200, { ok: true });
});

/* ----- courses and enrolment: the admin creates courses, gives each one a lecturer and enrols students per semester ----- */
const courseById = id => db.courses.find(c => c.id === id);
const enrolledIn = (courseId, semId) => db.enrollments.filter(e => e.courseId === courseId && e.semesterId === semId);
const courseView = (co, semId) => {
  const l = co.lecturerId ? userById(co.lecturerId) : null, d = db.departments.find(x => x.id === co.departmentId), p = db.programs.find(x => x.id === co.programId);
  return { id: co.id, code: co.code, title: co.title, credits: co.credits, year: co.year || null, departmentId: co.departmentId, departmentName: d ? d.name : '', programId: co.programId || '', programName: p ? p.name : '',
    lecturerId: co.lecturerId || '', lecturerName: l ? l.name : '', enrolled: semId ? enrolledIn(co.id, semId).length : 0 };
};
function cleanCourse(b, selfId) {
  const code = str(b.code, 20, 'Course code', true).toUpperCase();
  if (!/^[A-Z0-9._\/ -]{2,20}$/.test(code)) throw bad('Course code may use letters, numbers and . _ - / only.');
  if (db.courses.some(x => x.id !== selfId && x.code === code)) throw bad('That course code already exists.');
  const dep = db.departments.find(d => d.id === b.departmentId);
  if (!dep) throw bad('Choose a department.');
  let programId = '';
  if (b.programId) { const p = db.programs.find(x => x.id === b.programId); if (!p) throw bad('Program not found.'); programId = p.id; }
  let year = null;
  if (b.year !== undefined && b.year !== null && b.year !== '') year = cleanYear(b.year);
  const credits = Number(b.credits === undefined || b.credits === '' ? 3 : b.credits);
  if (!Number.isFinite(credits) || credits < 0 || credits > 30) throw bad('Credits must be a number from 0 to 30.');
  let lecturerId = '';
  if (b.lecturerId) { const l = userById(b.lecturerId); if (!l || l.role !== 'lecturer') throw bad('Choose a lecturer from the list.'); lecturerId = l.id; }
  return { code, title: str(b.title, 120, 'Course title', true), departmentId: dep.id, programId, year, credits, lecturerId };
}
route('GET', '/api/courses', ['admin', 'lecturer'], c => {
  const sem = semById(c.query.semesterId) || db.semesters.find(s => s.active) || null;
  let list = db.courses;
  if (c.user.role === 'lecturer') list = list.filter(x => x.lecturerId === c.user.id);
  else {
    if (c.query.departmentId) list = list.filter(x => x.departmentId === c.query.departmentId);
    if (c.query.programId) list = list.filter(x => x.programId === c.query.programId);
  }
  send(c.res, 200, { courses: list.slice().sort((a, b) => a.code.localeCompare(b.code)).map(x => courseView(x, sem ? sem.id : '')), semesterId: sem ? sem.id : '' });
});
route('POST', '/api/courses', ['admin'], async c => {
  const co = Object.assign({ id: uid('C') }, cleanCourse(await readJson(c.req)));
  db.courses.push(co); audit(c.user, 'course', 'Added ' + co.code); saveDb();
  send(c.res, 201, { course: courseView(co, '') });
});
route('PUT', '/api/courses/:id', ['admin'], async c => {
  const co = courseById(c.params.id);
  if (!co) throw new HttpError(404, 'Course not found.');
  Object.assign(co, cleanCourse(Object.assign({}, co, await readJson(c.req)), co.id));
  audit(c.user, 'course', 'Edited ' + co.code); saveDb();
  send(c.res, 200, { course: courseView(co, '') });
});
route('DELETE', '/api/courses/:id', ['admin'], c => {
  const co = courseById(c.params.id);
  if (!co) throw new HttpError(404, 'Course not found.');
  db.enrollments = db.enrollments.filter(e => e.courseId !== co.id);
  db.results = db.results.filter(r => r.courseId !== co.id);
  db.courses = db.courses.filter(x => x !== co);
  audit(c.user, 'course', 'Deleted ' + co.code); saveDb();
  send(c.res, 200, { ok: true });
});
const studentRow = (s, extra) => Object.assign({ id: s.id, name: s.name, loginId: s.loginId, rollNo: s.rollNo || '', phone: s.phone || '', programId: s.programId || '', departmentId: s.departmentId || '', year: s.year || null, active: s.active !== false }, extra || {});
route('GET', '/api/courses/:id/students', ['admin', 'lecturer'], c => {
  const co = courseById(c.params.id), sem = semById(c.query.semesterId);
  if (!co) throw new HttpError(404, 'Course not found.');
  if (!sem) throw bad('Choose a semester.');
  if (c.user.role === 'lecturer' && co.lecturerId !== c.user.id) throw new HttpError(403, 'This is not your course.');
  const rows = enrolledIn(co.id, sem.id).map(e => studentById(e.studentId)).filter(Boolean).sort((a, b) => a.name.localeCompare(b.name)).map(s => studentRow(s));
  send(c.res, 200, { course: courseView(co, sem.id), rows });
});
route('POST', '/api/courses/:id/enroll', ['admin'], async c => {
  const co = courseById(c.params.id);
  if (!co) throw new HttpError(404, 'Course not found.');
  const b = await readJson(c.req), sem = semById(b.semesterId);
  if (!sem) throw bad('Choose a semester.');
  let list;
  if (Array.isArray(b.studentIds)) list = b.studentIds.map(studentById).filter(Boolean);
  else {
    if (!b.programId) throw bad('Choose a program, or pick students.');
    list = db.users.filter(u => u.role === 'student' && u.active !== false && u.programId === b.programId && (!b.year || u.year === Number(b.year)));
  }
  if (!list.length) throw bad('No students matched.');
  let added = 0;
  list.forEach(s => {
    if (db.enrollments.some(e => e.studentId === s.id && e.courseId === co.id && e.semesterId === sem.id)) return;
    db.enrollments.push({ id: uid('E'), studentId: s.id, courseId: co.id, semesterId: sem.id, at: Date.now() }); added++;
    notify(s.id, 'You were enrolled in ' + co.code + ' ' + co.title + ' for ' + sem.name + '.');
  });
  audit(c.user, 'enrolment', 'Enrolled ' + added + ' student(s) in ' + co.code + ' for ' + sem.name); saveDb();
  send(c.res, 200, { added, skipped: list.length - added });
});
route('DELETE', '/api/courses/:id/enroll/:studentId', ['admin'], c => {
  const before = db.enrollments.length;
  db.enrollments = db.enrollments.filter(e => !(e.courseId === c.params.id && e.studentId === c.params.studentId && e.semesterId === c.query.semesterId));
  if (db.enrollments.length === before) throw new HttpError(404, 'Enrolment not found.');
  db.results = db.results.filter(r => !(r.courseId === c.params.id && r.studentId === c.params.studentId && r.semesterId === c.query.semesterId));
  audit(c.user, 'enrolment', 'Removed an enrolment'); saveDb();
  send(c.res, 200, { ok: true });
});
/* a lecturer's student list: everyone enrolled in any of their courses, for one semester */
route('GET', '/api/lecturer/students', ['lecturer'], c => {
  const sem = semById(c.query.semesterId) || db.semesters.find(s => s.active);
  if (!sem) return send(c.res, 200, { rows: [], courses: [], semesterId: '' });
  const mine = db.courses.filter(x => x.lecturerId === c.user.id);
  const use = c.query.courseId ? mine.filter(x => x.id === c.query.courseId) : mine;
  const text = String(c.query.q || '').toLowerCase(), by = new Map();
  use.forEach(co => enrolledIn(co.id, sem.id).forEach(e => {
    const s = studentById(e.studentId); if (!s) return;
    if (!by.has(s.id)) by.set(s.id, studentRow(s, { courses: [] }));
    by.get(s.id).courses.push(co.code);
  }));
  let rows = [...by.values()].filter(r => !text || r.name.toLowerCase().includes(text) || r.loginId.toLowerCase().includes(text) || r.rollNo.toLowerCase().includes(text));
  rows.sort((a, b) => a.name.localeCompare(b.name));
  send(c.res, 200, { rows, semesterId: sem.id, courses: mine.map(x => courseView(x, sem.id)) });
});
/* ----- results: lecturers enter marks, publish them, students see grades and GPA ----- */
const MAX_CW = 40, MAX_EX = 60;                                  // coursework out of 40, exam out of 60
const GRADES = [[80, 'A', 4], [70, 'B', 3], [60, 'C', 2], [50, 'D', 1], [0, 'F', 0]];
const gradeOf = t => { const g = GRADES.find(x => t >= x[0]); return { grade: g[1], points: g[2] }; };
const resultOf = (stuId, courseId, semId) => db.results.find(r => r.studentId === stuId && r.courseId === courseId && r.semesterId === semId);
function cleanMark(v, max, label) {
  if (v === '' || v === null || v === undefined) return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0 || n > max) throw bad(label + ' must be a number from 0 to ' + max + '.');
  return round2(n);
}
function markableCourse(c) {
  const co = courseById(c.params.courseId || c.query.courseId);
  if (!co) throw new HttpError(404, 'Course not found.');
  if (c.user.role !== 'admin' && co.lecturerId !== c.user.id) throw new HttpError(403, 'You can only enter marks for courses you teach.');
  return co;
}
const resultSem = c => { const sm = semById((c.query && c.query.semesterId) || c.body_semesterId) || db.semesters.find(x => x.active); if (!sm) throw bad('There is no current semester yet.'); return sm; };
route('GET', '/api/results/courses', ['lecturer', 'admin'], c => {
  const sm = resultSem(c);
  const list = db.courses.filter(x => c.user.role === 'admin' || x.lecturerId === c.user.id).sort((a, b) => a.code.localeCompare(b.code)).map(co => {
    const enr = enrolledIn(co.id, sm.id), rs = enr.map(e => resultOf(e.studentId, co.id, sm.id)).filter(Boolean);
    return { id: co.id, code: co.code, title: co.title, lecturerName: (userById(co.lecturerId) || {}).name || '', enrolled: enr.length, entered: rs.filter(r => r.total !== null).length, published: rs.filter(r => r.published).length };
  });
  send(c.res, 200, { courses: list, semesterId: sm.id });
});
route('GET', '/api/results/sheet', ['lecturer', 'admin'], c => {
  const co = markableCourse(c), sm = resultSem(c);
  const rows = enrolledIn(co.id, sm.id).map(e => studentById(e.studentId)).filter(Boolean).map(st => {
    const r = resultOf(st.id, co.id, sm.id) || {};
    return { studentId: st.id, name: st.name, loginId: st.loginId, rollNo: st.rollNo || '', coursework: r.coursework === undefined ? null : r.coursework, exam: r.exam === undefined ? null : r.exam, total: r.total === undefined ? null : r.total, grade: r.grade || '', published: !!r.published };
  }).sort((a, b) => a.name.localeCompare(b.name));
  send(c.res, 200, { course: { id: co.id, code: co.code, title: co.title, credits: co.credits }, semesterId: sm.id, rows, maxCoursework: MAX_CW, maxExam: MAX_EX });
});
route('PUT', '/api/results/:courseId', ['lecturer', 'admin'], async c => {
  const b = await readJson(c.req); c.body_semesterId = b.semesterId;
  const co = markableCourse(c), sm = resultSem(c);
  if (!Array.isArray(b.entries) || b.entries.length > 2000) throw bad('Nothing to save.');
  const enrolled = new Set(enrolledIn(co.id, sm.id).map(e => e.studentId));
  const clean = b.entries.map(en => {
    if (!enrolled.has(en.studentId)) throw bad('A student in the list is not enrolled in this course.');
    const old = resultOf(en.studentId, co.id, sm.id);
    if (old && old.published) throw bad('These results are already published. Unpublish them first to change marks.');
    return { studentId: en.studentId, coursework: cleanMark(en.coursework, MAX_CW, 'Coursework'), exam: cleanMark(en.exam, MAX_EX, 'Exam'), old };
  });
  clean.forEach(en => {
    const both = en.coursework !== null && en.exam !== null, total = both ? round2(en.coursework + en.exam) : null, g = both ? gradeOf(total) : { grade: '', points: 0 };
    if (en.coursework === null && en.exam === null) { if (en.old) db.results = db.results.filter(r => r !== en.old); return; }
    const row = en.old || { id: uid('R'), studentId: en.studentId, courseId: co.id, semesterId: sm.id, published: false };
    Object.assign(row, { coursework: en.coursework, exam: en.exam, total, grade: g.grade, points: g.points, updatedAt: Date.now(), updatedBy: c.user.id });
    if (!en.old) db.results.push(row);
  });
  audit(c.user, 'results', 'Saved marks for ' + co.code + ' (' + clean.length + ' students)'); saveDb();
  send(c.res, 200, { ok: true, saved: clean.length });
});
route('POST', '/api/results/:courseId/publish', ['lecturer', 'admin'], async c => {
  const b = await readJson(c.req); c.body_semesterId = b.semesterId;
  const co = markableCourse(c), sm = resultSem(c), enr = enrolledIn(co.id, sm.id);
  const rows = enr.map(e => resultOf(e.studentId, co.id, sm.id));
  if (b.publish === false) {
    rows.filter(Boolean).forEach(r => { r.published = false; });
    audit(c.user, 'results', 'Unpublished results for ' + co.code); saveDb();
    return send(c.res, 200, { ok: true });
  }
  if (!enr.length) throw bad('Nobody is enrolled in this course for this semester.');
  const missing = rows.filter(r => !r || r.total === null).length;
  if (missing) throw bad(missing + ' student(s) still have no complete marks. Enter coursework and exam marks for everyone first.');
  rows.forEach(r => { if (!r.published) { r.published = true; r.publishedAt = Date.now(); notify(r.studentId, 'Your results for ' + co.code + ' ' + co.title + ' (' + sm.name + ') are now available. Open My Results.'); } });
  audit(c.user, 'results', 'Published results for ' + co.code + ' (' + sm.name + ')'); saveDb();
  send(c.res, 200, { ok: true });
});
route('GET', '/api/my/results', ['student'], c => {
  const by = new Map();
  db.results.filter(r => r.studentId === c.user.id && r.published).forEach(r => {
    const co = courseById(r.courseId), sm = semById(r.semesterId); if (!co || !sm) return;
    if (!by.has(sm.id)) by.set(sm.id, { semester: { id: sm.id, name: sm.name }, courses: [] });
    by.get(sm.id).courses.push({ code: co.code, title: co.title, credits: Number(co.credits) || 0, coursework: r.coursework, exam: r.exam, total: r.total, grade: r.grade, points: r.points });
  });
  const gpa = list => { const cr = list.reduce((n, x) => n + x.credits, 0); return cr ? round2(list.reduce((n, x) => n + x.points * x.credits, 0) / cr) : (list.length ? round2(list.reduce((n, x) => n + x.points, 0) / list.length) : 0); };
  const order = db.semesters.map(x => x.id), all = [];
  const semesters = [...by.values()].sort((a, b) => order.indexOf(b.semester.id) - order.indexOf(a.semester.id)).map(x => { x.courses.sort((a, b) => a.code.localeCompare(b.code)); all.push(...x.courses); return Object.assign(x, { credits: x.courses.reduce((n, k) => n + k.credits, 0), gpa: gpa(x.courses) }); });
  send(c.res, 200, { semesters, cgpa: gpa(all), credits: all.reduce((n, k) => n + k.credits, 0), scale: GRADES.map(g => ({ from: g[0], grade: g[1], points: g[2] })) });
});
/* ----- students pick their own courses for the current semester ----- */
const canTake = (stu, co) => co.departmentId === stu.departmentId && (!co.programId || co.programId === stu.programId) && (!co.year || co.year === stu.year);
route('GET', '/api/my/courses', ['student'], c => {
  const cur = db.semesters.find(x => x.active) || null, sem = semById(c.query.semesterId) || cur;
  const mine = db.enrollments.filter(e => e.studentId === c.user.id).map(e => {
    const co = courseById(e.courseId), sm = semById(e.semesterId); if (!co || !sm) return null;
    const v = courseView(co, ''); return { courseId: co.id, code: v.code, title: v.title, credits: v.credits, lecturerName: v.lecturerName, semester: { id: sm.id, name: sm.name }, at: e.at };
  }).filter(Boolean).sort((a, b) => b.at - a.at);
  const taken = new Set(mine.filter(x => sem && x.semester.id === sem.id).map(x => x.courseId));
  const available = sem && cur && sem.id === cur.id && cur.regOpen !== false ? db.courses.filter(co => canTake(c.user, co) && !taken.has(co.id)).sort((a, b) => a.code.localeCompare(b.code)).map(co => courseView(co, '')) : [];
  send(c.res, 200, { rows: mine, available, semesterId: sem ? sem.id : '', currentSemesterId: cur ? cur.id : '', canPick: !!(sem && cur && sem.id === cur.id && cur.regOpen !== false), regOpen: !cur || cur.regOpen !== false, maxCredits: cur ? (cur.maxCredits || 24) : 24, credits: sem ? mine.filter(x => x.semester.id === sem.id).reduce((n, x) => n + (Number(x.credits) || 0), 0) : 0 });
});
route('POST', '/api/my/courses', ['student'], async c => {
  const b = await readJson(c.req), co = courseById(b.courseId), cur = db.semesters.find(x => x.active);
  if (!co) throw new HttpError(404, 'Course not found.');
  if (!cur) throw bad('There is no current semester yet.');
  if (cur.regOpen === false) throw bad('Course registration for this semester is closed.');
  if (!canTake(c.user, co)) throw bad('This course is not open to your program or year.');
  if (db.settings.blockPickIfOwing) {
    const owed = round2(db.fees.filter(f => f.studentId === c.user.id).reduce((n, f) => n + (f.total - f.paid), 0));
    if (owed > 0) throw bad('You have an unpaid fee balance of ' + money(owed) + '. Please clear it with the accounts office before picking courses.');
  }
  const used = db.enrollments.filter(e => e.studentId === c.user.id && e.semesterId === cur.id).reduce((n, e) => { const x = courseById(e.courseId); return n + (x ? Number(x.credits) || 0 : 0); }, 0);
  if (used + (Number(co.credits) || 0) > (cur.maxCredits || 24)) throw bad('Picking this course would pass the maximum of ' + (cur.maxCredits || 24) + ' credits for the semester.');
  if (db.enrollments.some(e => e.studentId === c.user.id && e.courseId === co.id && e.semesterId === cur.id)) throw bad('You already picked this course.');
  db.enrollments.push({ id: uid('E'), studentId: c.user.id, courseId: co.id, semesterId: cur.id, at: Date.now() });
  if (co.lecturerId) notify(co.lecturerId, c.user.name + ' (' + (c.user.rollNo || c.user.loginId) + ') picked ' + co.code + ' for ' + cur.name + '.');
  audit(c.user, 'enrolment', 'Picked ' + co.code); saveDb();
  send(c.res, 200, { ok: true });
});
route('DELETE', '/api/my/courses/:courseId', ['student'], c => {
  const cur = db.semesters.find(x => x.active), before = db.enrollments.length;
  if (!cur) throw bad('There is no current semester yet.');
  db.enrollments = db.enrollments.filter(e => !(e.studentId === c.user.id && e.courseId === c.params.courseId && e.semesterId === cur.id));
  if (db.enrollments.length === before) throw new HttpError(404, 'You have not picked this course.');
  db.results = db.results.filter(r => !(r.studentId === c.user.id && r.courseId === c.params.courseId && r.semesterId === cur.id));
  audit(c.user, 'enrolment', 'Dropped a course'); saveDb();
  send(c.res, 200, { ok: true });
});

/* ----- lecturers pick the courses they teach, from their own department ----- */
route('GET', '/api/teaching', ['lecturer'], c => {
  const cur = db.semesters.find(x => x.active) || null, dep = db.departments.find(d => d.id === c.user.departmentId) || null;
  const list = dep ? db.courses.filter(x => x.departmentId === dep.id).sort((a, b) => a.code.localeCompare(b.code)) : [];
  send(c.res, 200, { department: dep ? { id: dep.id, name: dep.name } : null, courses: list.map(co => Object.assign(courseView(co, cur ? cur.id : ''), { mine: co.lecturerId === c.user.id, takenByOther: !!co.lecturerId && co.lecturerId !== c.user.id })) });
});
route('POST', '/api/teaching/:courseId', ['lecturer'], c => {
  const co = courseById(c.params.courseId);
  if (!co) throw new HttpError(404, 'Course not found.');
  if (!c.user.departmentId) throw bad('You have no department yet. Ask the administrator to assign one.');
  if (co.departmentId !== c.user.departmentId) throw bad('You can only pick courses from your own department.');
  if (co.lecturerId && co.lecturerId !== c.user.id) throw bad('Another lecturer already teaches this course. Ask the administrator to change it.');
  co.lecturerId = c.user.id; audit(c.user, 'course', 'Picked to teach ' + co.code); saveDb();
  send(c.res, 200, { ok: true });
});
route('DELETE', '/api/teaching/:courseId', ['lecturer'], c => {
  const co = courseById(c.params.courseId);
  if (!co) throw new HttpError(404, 'Course not found.');
  if (co.lecturerId !== c.user.id) throw bad('You are not teaching this course.');
  co.lecturerId = ''; audit(c.user, 'course', 'Stopped teaching ' + co.code); saveDb();
  send(c.res, 200, { ok: true });

});

/* ----- admin dashboard numbers ----- */
route('GET', '/api/stats', ['admin'], c => {
  const students = db.users.filter(u => u.role === 'student'), lecturers = db.users.filter(u => u.role === 'lecturer'), admins = db.users.filter(u => u.role === 'admin');
  const sem = db.semesters.find(s => s.active) || null;
  const fees = sem ? db.fees.filter(f => f.semesterId === sem.id) : [];
  const total = round2(fees.reduce((a, f) => a + f.total, 0)), paid = round2(fees.reduce((a, f) => a + f.paid, 0));
  const enr = sem ? db.enrollments.filter(e => e.semesterId === sem.id) : [];
  const enrolledIds = new Set(enr.map(e => e.studentId));
  const all = db.users;
  send(c.res, 200, {
    students: students.length, lecturers: lecturers.length, admins: admins.length,
    byDepartment: db.departments.map(d => ({ id: d.id, name: d.name, students: students.filter(s => s.departmentId === d.id).length, lecturers: lecturers.filter(l => l.departmentId === d.id).length, courses: db.courses.filter(x => x.departmentId === d.id).length })),
    byProgram: db.programs.map(p => ({ id: p.id, name: p.name, students: students.filter(s => s.programId === p.id).length })),
    byYear: [1, 2, 3, 4, 5, 6, 7, 8].map(y => ({ year: y, students: students.filter(s => s.year === y).length })).filter(x => x.students),
    semester: sem ? { id: sem.id, name: sem.name } : null,
    fees: { total, paid, balance: round2(total - paid), owing: fees.filter(f => f.total - f.paid > 0).length, recorded: fees.length },
    transcripts: { uploaded: sem ? db.transcripts.filter(t => t.semesterId === sem.id).length : 0, students: students.length },
    enrollment: { enrolledStudents: students.filter(s => enrolledIds.has(s.id)).length, notEnrolled: students.filter(s => !enrolledIds.has(s.id)).length, totalEnrollments: enr.length },
    courses: { total: db.courses.length, withoutLecturer: db.courses.filter(x => !x.lecturerId).length,
      top: db.courses.map(x => ({ id: x.id, code: x.code, title: x.title, enrolled: sem ? enrolledIn(x.id, sem.id).length : 0 })).sort((a, b) => b.enrolled - a.enrolled).slice(0, 8) },
    accounts: { total: all.length, active: all.filter(u => u.active !== false).length, inactive: all.filter(u => u.active === false).length, pendingFirstLogin: all.filter(u => u.mustChange).length, withoutRollNo: students.filter(s => !s.rollNo).length },
    recent: db.audit.slice(-10).reverse()
  });
});
/* ---------- web pages ---------- */
const LOGO_TYPES = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' };
function serveLogo(res) {
  for (const ext of Object.keys(LOGO_TYPES)) {
    const f = path.join(ROOT, 'logo' + ext);
    if (fs.existsSync(f)) {
      const data = fs.readFileSync(f);
      res.writeHead(200, { 'Content-Type': LOGO_TYPES[ext], 'Content-Length': data.length, 'Cache-Control': 'public, max-age=300' });
      return res.end(data);
    }
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('No logo');
}
function serveIndex(res) {
  fs.readFile(path.join(ROOT, 'index.html'), 'utf8', (err, html) => {
    if (err) { res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('index.html was not found. Put index.html in the same folder as server.js.'); }
    const nonce = crypto.randomBytes(16).toString('base64');
    html = html.replace(/<script>/g, '<script nonce="' + nonce + '">');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache',
      'Content-Security-Policy': "default-src 'self'; script-src 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    });
    res.end(html);
  });
}
function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { 'Content-Type': 'text/plain' }); return res.end('Method not allowed'); }
  if (pathname === '/' || pathname === '/index.html') return serveIndex(res);
  if (pathname === '/logo.png' || pathname === '/favicon.ico') return serveLogo(res);
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found');
}

/* ---------- server ---------- */
async function handle(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  const url = new URL(req.url, 'http://localhost');
  const sm = /^\/s\/([A-Za-z0-9]{8,32})(\/.*)$/.exec(url.pathname);
  if (sm) { req.slot = res.slot = sm[1]; url.pathname = sm[2]; }
  if (url.pathname.startsWith('/api/')) return handleApi(req, res, url);
  return serveStatic(req, res, url.pathname);
}
function fail(res, err) {
  if (res.headersSent) return res.destroy();
  if (err instanceof HttpError) {
    const body = { error: err.message }; if (err.code) body.code = err.code;
    return send(res, err.status, body);
  }
  console.error('Server error:', err);
  send(res, 500, { error: 'Something went wrong on the server.' });
}

/* ---------- start-up tasks ---------- */
function printBox(lines) {
  const w = Math.max.apply(null, lines.map(l => l.length)) + 4;
  console.log('\n' + '='.repeat(w));
  lines.forEach(l => console.log('  ' + l));
  console.log('='.repeat(w) + '\n');
}
async function ensureAdmin() {
  if (db.users.some(u => u.role === 'admin')) return;
  const pw = process.env.INITIAL_ADMIN_PASSWORD || tempPassword();
  db.users.push({ id: uid('U'), loginId: 'admin', name: 'System Administrator', role: 'admin', phone: '', active: true, mustChange: true, createdAt: Date.now(), passHash: await hashPassword(pw) });
  saveDb();
  printBox(['FIRST-TIME SETUP: administrator account created', 'Sign in with   ID: admin    Password: ' + pw, 'You will be asked to choose a new password straight away.']);
}
async function resetAdmin() {
  const a = db.users.find(u => u.role === 'admin' && u.loginId === 'admin') || db.users.find(u => u.role === 'admin');
  if (!a) { await ensureAdmin(); return; }
  const pw = tempPassword();
  a.passHash = await hashPassword(pw); a.mustChange = true; a.active = true;
  sessions.forEach((v, k) => { if (v.userId === a.id) sessions.delete(k); }); writeSessions();
  saveDb();
  printBox(['Administrator password reset', 'ID: ' + a.loginId + '    New temporary password: ' + pw]);
}
async function addDemo() {
  const pw = 'Demo12345', demoHash = await hashPassword(pw);
  const make = async (loginId, name, role, extra) => {
    if (findByLogin(loginId)) return;
    db.users.push(Object.assign({ id: uid('U'), loginId, name, role, phone: '', active: true, mustChange: false, createdAt: Date.now(), passHash: demoHash }, extra));
  };
  await make('lect001', 'Demo Lecturer', 'lecturer', { departmentId: 'D1' });
  await make('STU2026001', 'Demo Student One', 'student', { rollNo: 'R001', programId: 'P1', departmentId: 'D1', year: 1, phone: '+211 912 000 001' });
  await make('STU2026002', 'Demo Student Two', 'student', { rollNo: 'R002', programId: 'P2', departmentId: 'D1', year: 1 });
  await make('STU2026003', 'Demo Student Three', 'student', { rollNo: 'R003', programId: 'P3', departmentId: 'D4', year: 2 });
  if (!findByLogin('STU2026010')) await addDemoFull(make);
  saveDb();
  printBox(['DEMO accounts added (for testing only - delete them before real use)', 'Password for all: ' + pw, 'Lecturer: lect001     Students: STU2026001, STU2026002, STU2026003']);
}

/* A fuller demo (about 60 students, courses, fees, news) so every page looks lived-in. Used only with --demo. */
async function addDemoFull(make) {
  let seedN = 7; const rnd = () => (seedN = (seedN * 1103515245 + 12345) % 2147483648) / 2147483648, pick = a => a[Math.floor(rnd() * a.length)];
  [{ id: 'P4', departmentId: 'D3', name: 'Bachelor of Laws', level: 'Bachelor', years: 4 }, { id: 'P5', departmentId: 'D2', name: 'Bachelor of Economics', level: 'Bachelor', years: 4 }]
    .forEach(p => { if (!db.programs.find(x => x.id === p.id)) db.programs.push(p); });
  const first = ['Deng', 'Achol', 'Garang', 'Nyandeng', 'Majok', 'Ayen', 'Kuol', 'Akech', 'Lual', 'Nyibol', 'Mading', 'Adut', 'Chol', 'Abuk', 'Thon', 'Yar', 'Biar', 'Awut', 'Panther', 'Rebecca', 'Joseph', 'Mary', 'Peter', 'Grace', 'Samuel', 'Esther', 'David', 'Sarah', 'Moses', 'Ruth'];
  const last = ['Mabior', 'Atem', 'Ajak', 'Bol', 'Dut', 'Kiir', 'Malual', 'Wol', 'Makuei', 'Lado', 'Juma', 'Taban', 'Loro', 'Wani', 'Yangi', 'Okello', 'Duku', 'Ladu', 'Mayen', 'Aguer'];
  const lecturers = [['lect002', 'Dr. James Wani', 'D1'], ['lect003', 'Prof. Rose Lado', 'D2'], ['lect004', 'Mr. Daniel Okello', 'D4'], ['lect005', 'Ms. Agnes Duku', 'D3'], ['lect006', 'Dr. Paul Mayen', 'D4'], ['lect007', 'Mrs. Mary Taban', 'D1']];
  for (const l of lecturers) await make(l[0], l[1], 'lecturer', { departmentId: l[2], phone: '+211 92' + (1000000 + Math.floor(rnd() * 8999999)) });
  const lect = d => db.users.filter(u => u.role === 'lecturer' && u.departmentId === d);
  const progs = db.programs.slice();
  for (let i = 4; i <= 63; i++) {
    const p = pick(progs), name = pick(first) + ' ' + pick(last);
    await make('STU2026' + String(i).padStart(3, '0'), name, 'student', { rollNo: 'R' + String(i).padStart(3, '0'), programId: p.id, departmentId: p.departmentId, year: 1 + Math.floor(rnd() * Math.min(3, p.years)), phone: '+211 91' + (1000000 + Math.floor(rnd() * 8999999)) });
  }
  const titles = { D1: ['Programming Fundamentals', 'Database Systems', 'Computer Networks', 'Web Development', 'Discrete Mathematics'], D2: ['Principles of Economics', 'Development Economics', 'Statistics for Social Science', 'Public Finance'], D3: ['Constitutional Law', 'Law of Contract', 'Criminal Law', 'Legal Writing'], D4: ['Principles of Management', 'Financial Accounting', 'Marketing', 'Business Ethics', 'Entrepreneurship'] };
  const codes = { D1: 'CSC', D2: 'ECO', D3: 'LAW', D4: 'MGT' };
  for (const d of Object.keys(titles)) titles[d].forEach((t, k) => {
    const ls = lect(d), prog = db.programs.filter(p => p.departmentId === d);
    if (!db.courses.find(c => c.code === codes[d] + (101 + k))) db.courses.push({ id: uid('C'), code: codes[d] + (101 + k), title: t, departmentId: d, programId: prog.length === 1 ? prog[0].id : '', year: 1 + (k % 3), credits: 3 + (k % 2), lecturerId: ls.length && k !== 4 ? ls[k % ls.length].id : '' });
  });
  const sem = db.semesters.find(x => x.active);
  const fee = { P1: 1200, P2: 800, P3: 1100, P4: 1300, P5: 1000 };
  db.users.filter(u => u.role === 'student').forEach(u => {
    const mine = db.courses.filter(c => c.departmentId === u.departmentId && (!c.programId || c.programId === u.programId) && (!c.year || c.year === u.year)).slice(0, 4);
    mine.forEach(c => { if (!db.enrollments.find(e => e.studentId === u.id && e.courseId === c.id)) db.enrollments.push({ id: uid('E'), studentId: u.id, courseId: c.id, semesterId: sem.id, at: Date.now() - Math.floor(rnd() * 5) * 86400000 }); });
    if (!db.fees.find(f => f.studentId === u.id && f.semesterId === sem.id)) { const total = fee[u.programId] || 1000, r = rnd(); db.fees.push({ studentId: u.id, semesterId: sem.id, total, paid: r < .3 ? total : (r < .8 ? Math.round(total * (0.3 + rnd() * 0.5) / 10) * 10 : 0), updatedAt: Date.now() }); }
  });
  db.courses.filter(c => /^(CSC101|CSC102|LAW101|MGT101)$/.test(c.code)).forEach((c, k) => {
    db.enrollments.filter(e => e.courseId === c.id && e.semesterId === sem.id).forEach(e => {
      const cw = Math.round(14 + rnd() * 24), ex = Math.round(22 + rnd() * 36), total = cw + ex, g = gradeOf(total);
      db.results.push({ id: uid('R'), studentId: e.studentId, courseId: c.id, semesterId: sem.id, coursework: cw, exam: ex, total, grade: g.grade, points: g.points, published: k < 2, publishedAt: Date.now(), updatedAt: Date.now() });
    });
  });
  const admin = db.users.find(u => u.role === 'admin'), day = 86400000;
  [['Welcome to the new Student Portal', 'You can now see your courses, fees and transcripts online. Sign in with your registration number.', 'all', 6, true],
   ['Semester 1 course registration is open', 'Pick your courses from the My Courses page before the end of the month. Maximum credits per semester apply.', 'student', 4, false],
   ['Mid-semester examinations timetable', 'The timetable is at the registry office notice board. Please check your venues early.', 'all', 2, false],
   ['Staff meeting on Friday', 'All lecturers are invited to the staff meeting in the main hall at 10:00.', 'lecturer', 1, false],
   ['Fee payment reminder', 'Please clear any balance at the Finance Office before the examinations. Quote your registration number.', 'student', 0, false]]
    .forEach(a => db.announcements.push({ id: uid('A'), title: a[0], body: a[1], audience: a[2], by: admin.id, byName: admin.name, byRole: 'admin', at: Date.now() - a[3] * day, pinned: a[4] }));
}

async function main() {
  loadDb(); loadSessions(); dailyBackup();
  DUMMY_HASH = await hashPassword('not-a-real-password-1');
  await ensureAdmin();
  if (process.argv.includes('--reset-admin')) { await resetAdmin(); process.exit(0); }
  if (process.argv.includes('--demo')) await addDemo();
  setInterval(dailyBackup, 1 * 3600 * 1000).unref();
  setInterval(() => { sessions.forEach((v, k) => { if (v.exp < Date.now()) sessions.delete(k); }); }, 3600 * 1000).unref();

  const server = http.createServer((req, res) => { handle(req, res).catch(err => fail(res, err)); });
  server.requestTimeout = 10 * 60 * 1000;      // slow connections can still finish uploading
  server.headersTimeout = 30 * 1000;
  server.on('error', e => {
    console.error(e.code === 'EADDRINUSE' ? 'Port ' + PORT + ' is already in use. Is the portal already running in another window?' : 'Server error: ' + e.message);
    process.exit(1);
  });
  server.listen(PORT, HOST, () => {
    const lines = ['Starford Student Portal is running', 'On this computer, open:  http://localhost:' + PORT];
    Object.values(os.networkInterfaces()).flat().filter(i => i && i.family === 'IPv4' && !i.internal)
      .forEach(i => lines.push('Other computers/phones on the same network:  http://' + i.address + ':' + PORT));
    lines.push('Data is saved in: ' + DATA_DIR, 'Keep this window open. Press Ctrl+C to stop.');
    printBox(lines);
  });
  const stop = () => { writeSessions(); try { if (sqlite) sqlite.close(); } catch (e) { /* closing anyway */ } process.exit(0); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
process.on('unhandledRejection', e => console.error('Unhandled problem:', e));
process.on('uncaughtException', e => console.error('Unexpected error:', e));
main().catch(e => { console.error('\nTHE PORTAL COULD NOT START.\nReason: ' + (e && e.message ? e.message : e) + '\n' + (e && e.stack ? e.stack : '')); process.exit(1); });
