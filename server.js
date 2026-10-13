// MYC 1989 back office server
// Run:  npm init -y && npm install express && node server.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-this-secret-before-going-live';
const USERS_FILE = path.join(__dirname, 'users.json');

const app = express();
app.use(express.json({ limit: '4mb' }));
// Allow the page to call the API even when opened from Live Server (port 5501)
app.use((req, res, next) => {
  res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.static(__dirname)); // serves index.html and myc-logo.jpeg

/* ---------- users (stored in users.json) ---------- */
const readUsers = () => { try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return []; } };
const writeUsers = u => fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2));

const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) =>
  salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
const verify = (pw, stored) => {
  const [salt, h] = stored.split(':');
  const test = crypto.scryptSync(pw, salt, 64);
  return crypto.timingSafeEqual(test, Buffer.from(h, 'hex'));
};

/* ---------- signed tokens (HMAC, 7 days) ---------- */
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const sign = data => crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
const makeToken = user => {
  const body = b64({ id: user.id, exp: Date.now() + 7 * 864e5 });
  return body + '.' + sign(body);
};
function readToken(t) {
  const [body, sig] = (t || '').split('.');
  if (!body || !sig || sig !== sign(body)) return null;
  const p = JSON.parse(Buffer.from(body, 'base64url').toString());
  return p.exp > Date.now() ? p : null;
}
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, perms: permsOf(u) });

function auth(req, res, next) {
  const p = readToken((req.headers.authorization || '').replace('Bearer ', ''));
  const user = p && readUsers().find(u => u.id === p.id);
  if (!user) return res.status(401).json({ error: 'Please sign in again.' });
  req.user = user;
  next();
}

/* ---------- auth routes ---------- */
app.post('/api/signup', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Enter your name, email and password.' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const users = readUsers();
  if (users.length) return res.status(403).json({ error: 'Sign up is closed. Ask an admin to create your account (Settings → Team).' });
  if (users.some(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'An account with this email already exists.' });
  const user = { id: crypto.randomUUID(), name, email: email.toLowerCase(), password: hash(password) };
  users.push(user);
  writeUsers(users);
  res.json({ token: makeToken(user), user: publicUser(user) });
});

app.post('/api/signin', (req, res) => {
  const { email, password } = req.body;
  const user = readUsers().find(u => u.email === (email || '').toLowerCase());
  if (!user || !verify(password || '', user.password)) return res.status(401).json({ error: 'Incorrect email or password.' });
  res.json({ token: makeToken(user), user: publicUser(user) });
});

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

/* ---------- dashboard data (sample data: replace with your database) ---------- */
app.get('/api/dashboard', auth, (req, res) => {
  res.json({
    stats: [
      { label: 'Total products', icon: '◫', value: 420, change: 12, prev: 375 },
      { label: 'On promotion', icon: '%', value: 38, change: 12, prev: 34 },
      { label: 'Out of stock', icon: '▢', value: 14, change: 12, prev: 12 },
      { label: 'Clients with no orders', icon: '☺', value: 561, change: 12, prev: 500 }
    ],
    top: [
      { name: 'Denim jacket', pct: 45 },
      { name: 'Classic tee', pct: 30 },
      { name: 'Chino trousers', pct: 15 },
      { name: 'Others', pct: 10 }
    ],
    categories: [
      { name: 'Tees & tops', pct: 48, sales: 860 },
      { name: 'Outerwear', pct: 32, sales: 580 },
      { name: 'Bottoms', pct: 20, sales: 360 }
    ],
    revenue: {
      total: 194127, change: 12,
      labels: ['Oct 7', 'Oct 8', 'Oct 9', 'Oct 10', 'Oct 11', 'Oct 12', 'Oct 13'],
      thisWeek: [24000, 31000, 27000, 38000, 48000, 34000, 41000],
      lastWeek: [20000, 25000, 24000, 29000, 28000, 30000, 27000]
    },
    products: [
      { id: '#MYC-001', name: 'Denim jacket', category: 'Outerwear', price: 14500, stock: 42, promo: true },
      { id: '#MYC-002', name: 'Classic tee', category: 'Tees & tops', price: 3900, stock: 210, promo: false },
      { id: '#MYC-003', name: 'Chino trousers', category: 'Bottoms', price: 8900, stock: 65, promo: true },
      { id: '#MYC-004', name: 'Oxford shirt', category: 'Tees & tops', price: 7400, stock: 0, promo: false },
      { id: '#MYC-005', name: 'Bomber jacket', category: 'Outerwear', price: 18900, stock: 18, promo: false },
      { id: '#MYC-006', name: 'Cargo shorts', category: 'Bottoms', price: 6200, stock: 0, promo: false }
    ]
  });
});

/* ---------- products, suppliers, reports, settings (sample data) ---------- */
const P = [
  ['1235631','Ceylon Cotton Mills','Midi denim skirt A-line','👗','28.09.2026','03.10.2026','Delivering','Cash on delivery',28780],
  ['5235631','Denim Works','Black and white T-shirt','👕','28.09.2026','03.10.2026','Confirmed','Card',15400],
  ['1205631','ThreadLogix','Floral summer dress','👗','29.09.2026','04.10.2026','Shipped','Cash on delivery',35600],
  ['1235632','Ceylon Cotton Mills','Classic grey sweatshirt','🧥','30.09.2026','05.10.2026','Delivering','Card',22400],
  ['1235633','Denim Works','Slim fit jeans','👖','01.10.2026','06.10.2026','Delivering','Card',32700],
  ['1235634','PakTextile Co.','Oxford shirt','👔','02.10.2026','07.10.2026','Confirmed','Cash on delivery',18900],
  ['1235635','Zip & Button Co.','Bomber jacket','🧥','03.10.2026','08.10.2026','Shipped','Card',41500],
  ['1235636','NovaDye Industries','Cargo shorts','🩳','04.10.2026','09.10.2026','Confirmed','Card',12300]
];
app.get('/api/products', auth, (req, res) => res.json(P.map(([num, supplier, product, icon, ordered, delivery, status, payment, amount]) =>
  ({ num, supplier, product, icon, ordered, delivery, status, payment, amount }))));

const suppliers = [
  { name: 'Ceylon Cotton Mills', loc: 'Colombo, Sri Lanka', status: 'Active', last: 'Oct 5, 2026' },
  { name: 'PakTextile Co.', loc: 'Karachi, Pakistan', status: 'Inactive', last: 'Oct 6, 2026' },
  { name: 'Denim Works', loc: 'Istanbul, Turkey', status: 'Active', last: 'Oct 12, 2026' },
  { name: 'ThreadLogix', loc: 'Berlin, Germany', status: 'Pending', last: 'Sep 30, 2026' },
  { name: 'Zip & Button Co.', loc: 'Tirupur, India', status: 'Active', last: 'Oct 6, 2026' },
  { name: 'NovaDye Industries', loc: 'Dhaka, Bangladesh', status: 'Active', last: 'Oct 6, 2026' }
];
app.get('/api/suppliers', auth, (req, res) => res.json({
  suppliers,
  chats: [
    { name: 'Ceylon Cotton Mills', msg: 'Sent a message', time: '12:55 pm' },
    { name: 'ThreadLogix', msg: 'Sent a photo', time: '12:55 pm' },
    { name: 'Denim Works', msg: 'Sent a message', time: '12:40 pm' }
  ],
  activity: [
    { who: 'Nimal Perera', what: 'accepted new deals', when: 'Today, 10:24 AM' },
    { who: 'AI', what: 'suggested restocking 3 low-stock products', when: 'Today, 09:18 AM' },
    { who: 'Emily Zhang', what: 'updated documents for supplier deals', when: 'Today, 10:24 AM' }
  ]
}));
app.post('/api/suppliers', auth, can('suppliers'), (req, res) => {
  const t = k => String(req.body[k] || '').trim().slice(0, 120);
  const s = { name: t('company'), contact: (t('first') + ' ' + t('last')).trim(), mobile: t('mobile'), email: t('email'), loc: t('address'), status: 'Active', last: '-' };
  if (!t('first') || !s.name) return res.status(400).json({ error: 'First name and company name are required.' });
  suppliers.unshift(s);
  res.json(s);
});

const by = ['Martin Bats', 'John Li', 'Jacob Jones', 'Gloria Rich', 'Albert Flores', 'Ronald Richards'];
let reports = [
  ['Inventory Report', 'Custom', 'Report October 2026', '13.10.2026'],
  ['Workflow Report', 'Template', 'Workflow report', '12.10.2026'],
  ['Monthly Report', 'Template', 'Monthly report September 2026', '10.10.2026'],
  ['Wholesalers Report', 'Custom', 'Wholesalers report September 2026', '08.10.2026'],
  ['Competitor Analytics', 'Template', 'Analytics of the index of competitors', '05.10.2026'],
  ['Workflow Estimation', 'Custom', '-', '03.10.2026'],
  ['Quarterly Report', 'Custom', 'Quarterly report Q3 2026', '01.10.2026'],
  ['Weekly Report', 'Template', 'Weekly report 1-7 Oct 2026', '30.09.2026'],
  ['Inventory Report', 'Custom', '-', '24.09.2026'],
  ['Inventory Report', 'Custom', 'Inventory report 2026', '18.09.2026'],
  ['Returns Report', 'Custom', 'Returns and exchanges', '10.09.2026'],
  ['Sales by Category', 'Template', 'Sales by category August 2026', '02.09.2026']
].map(([name, type, desc, date], i) => ({ id: 'r' + i, name, type, by: by[i % by.length], desc, date }));
app.get('/api/reports', auth, (req, res) => res.json(reports));
app.post('/api/reports', auth, (req, res) => {
  const name = String(req.body.name || '').slice(0, 80);
  if (!name) return res.status(400).json({ error: 'Enter a report name.' });
  const d = new Date(), p = n => String(n).padStart(2, '0');
  const r = { id: 'r' + Date.now(), name, type: 'Custom', by: req.user.name, desc: '-', date: `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()}` };
  reports.unshift(r);
  res.json(r);
});
app.delete('/api/reports', auth, (req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
  reports = reports.filter(r => !ids.includes(r.id));
  res.json({ ok: true });
});

const ch = (push, email, sms) => ({ push, email, sms });
const defaultSettings = () => ({ orders: ch(1, 1, 0), stock: ch(1, 0, 0), messages: ch(1, 1, 0), suppliers: ch(0, 0, 0), reports: ch(0, 1, 0) });
app.get('/api/settings', auth, (req, res) => res.json({ ...defaultSettings(), ...(req.user.settings || {}) }));
app.post('/api/settings', auth, (req, res) => {
  const clean = defaultSettings();
  for (const k in clean) for (const c in clean[k]) clean[k][c] = req.body[k] && req.body[k][c] ? 1 : 0;
  const users = readUsers();
  users.find(u => u.id === req.user.id).settings = clean;
  writeUsers(users);
  res.json(clean);
});

/* ---------- store data, roles, team, profile, OTP, orders ---------- */
let nodemailer = null; try { nodemailer = require('nodemailer'); } catch {}
const MODS = ['dashboard', 'reports', 'categories', 'warehouse', 'products', 'grn', 'suppliers', 'settings'];
const DBF = path.join(__dirname, 'data.json');
let DB; try { DB = JSON.parse(fs.readFileSync(DBF, 'utf8')); } catch { DB = {}; }
DB = { categories: [], warehouses: [], products: [], grns: [], roles: [], store: {}, ...DB };
const save = () => fs.writeFileSync(DBF, JSON.stringify(DB));
function permsOf(u) { return u.roleId ? ((DB.roles.find(r => r.id === u.roleId) || {}).perms || []) : MODS; }
function can(m) { return (req, res, next) => permsOf(req.user).includes(m) ? next() : res.status(403).json({ error: 'You do not have access to this.' }); }
const uid = () => 'x' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
const today = () => new Date().toISOString().slice(0, 10);

const COLS = {
  categories: ['categories', ['name', 'description'], ['name']],
  warehouses: ['warehouse', ['name', 'location', 'contact'], ['name']],
  products: ['products', ['code', 'name', 'categoryId', 'qty', 'cost', 'price', 'mrp', 'status', 'image'], ['code', 'name']],
  grns: ['grn', ['supplier', 'warehouseId', 'productId', 'qty', 'cost', 'date'], ['supplier', 'productId']],
  roles: ['settings', ['name', 'perms'], ['name']]
};
const NUM = ['qty', 'cost', 'price', 'mrp'];
function pick(c, b) {
  const o = {};
  for (const k of COLS[c][1]) if (b[k] !== undefined) {
    o[k] = NUM.includes(k) ? Math.max(0, Number(b[k]) || 0)
      : k === 'perms' ? (Array.isArray(b[k]) ? b[k].filter(x => MODS.includes(x)) : [])
      : String(b[k]).trim().slice(0, k === 'image' ? 600000 : 200);
  }
  return o;
}
const colOk = (req, res, next) => COLS[req.params.c] ? next() : res.status(404).json({ error: 'Not found' });
const colCan = (req, res, next) => can(COLS[req.params.c][0])(req, res, next);
app.get('/api/data/:c', auth, colOk, (req, res) => res.json(DB[req.params.c]));
app.post('/api/data/:c', auth, colOk, colCan, (req, res) => {
  const c = req.params.c, o = pick(c, req.body);
  if (COLS[c][2].some(k => !o[k])) return res.status(400).json({ error: 'Please fill in the required fields.' });
  if (c === 'products' && DB.products.some(p => p.code === o.code)) return res.status(409).json({ error: 'That product code already exists.' });
  Object.assign(o, { id: uid() });
  if (c === 'products') { o.created = today(); o.status = o.status || 'Active'; }
  if (c === 'grns') {
    o.grnNo = 'GRN-' + String(DB.grns.length + 1).padStart(4, '0');
    const p = DB.products.find(x => x.id === o.productId);
    if (!p) return res.status(400).json({ error: 'Choose a product.' });
    p.qty += o.qty || 0; if (o.cost) p.cost = o.cost;
  }
  DB[c].unshift(o); save(); res.json(o);
});
app.put('/api/data/:c/:id', auth, colOk, colCan, (req, res) => {
  const c = req.params.c, item = DB[c].find(x => x.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  const o = pick(c, req.body);
  if (c === 'products' && o.code && DB.products.some(p => p.code === o.code && p.id !== item.id)) return res.status(409).json({ error: 'That product code already exists.' });
  if (COLS[c][2].some(k => k in o && !o[k])) return res.status(400).json({ error: 'Please fill in the required fields.' });
  Object.assign(item, o); save(); res.json(item);
});
app.delete('/api/data/:c/:id', auth, colOk, colCan, (req, res) => {
  const c = req.params.c;
  if (c === 'roles' && readUsers().some(u => u.roleId === req.params.id)) return res.status(409).json({ error: 'This role is assigned to users.' });
  DB[c] = DB[c].filter(x => x.id !== req.params.id); save(); res.json({ ok: true });
});

/* team */
const teamUser = u => ({ id: u.id, name: u.name, email: u.email, mobile: u.mobile || '', roleId: u.roleId || '' });
app.get('/api/team', auth, (req, res) => res.json(readUsers().map(teamUser)));
app.post('/api/team', auth, can('settings'), (req, res) => {
  const b = req.body, t = k => String(b[k] || '').trim().slice(0, 100), email = t('email').toLowerCase();
  if (!t('firstName') || !email || !b.password) return res.status(400).json({ error: 'First name, email and password are required.' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (b.password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (b.password !== b.confirm) return res.status(400).json({ error: 'Passwords do not match.' });
  if (!DB.roles.some(r => r.id === b.roleId)) return res.status(400).json({ error: 'Choose a role.' });
  const users = readUsers();
  if (users.some(u => u.email === email)) return res.status(409).json({ error: 'A user with this email already exists.' });
  const u = { id: crypto.randomUUID(), name: (t('firstName') + ' ' + t('lastName')).trim(), email, mobile: t('mobile'), roleId: b.roleId, password: hash(b.password) };
  users.push(u); writeUsers(users); res.json(teamUser(u));
});
app.delete('/api/team/:id', auth, can('settings'), (req, res) => {
  const users = readUsers(), u = users.find(x => x.id === req.params.id);
  if (!u || !u.roleId || u.id === req.user.id) return res.status(400).json({ error: 'This user cannot be removed.' });
  writeUsers(users.filter(x => x.id !== u.id)); res.json({ ok: true });
});

/* profile */
app.get('/api/profile', auth, (req, res) => {
  const u = req.user;
  res.json({ me: { name: u.name, email: u.email, phone: u.phone || '', dob: u.dob || '', nic: u.nic || '' }, store: DB.store });
});
app.put('/api/profile', auth, (req, res) => {
  const users = readUsers(), u = users.find(x => x.id === req.user.id), t = (v, n = 120) => String(v ?? '').trim().slice(0, n);
  if (req.body.me) {
    const m = req.body.me, email = t(m.email).toLowerCase();
    if (!t(m.name) || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter your name and a valid email.' });
    if (users.some(x => x.id !== u.id && x.email === email)) return res.status(409).json({ error: 'That email is already used.' });
    Object.assign(u, { name: t(m.name), email, phone: t(m.phone, 30), dob: t(m.dob, 10), nic: t(m.nic, 20) });
    writeUsers(users);
  }
  if (req.body.store) {
    if (!permsOf(req.user).includes('settings')) return res.status(403).json({ error: 'You do not have access to this.' });
    DB.store = { phone: t(req.body.store.phone, 30), email: t(req.body.store.email) }; save();
  }
  res.json({ user: publicUser(u), store: DB.store });
});

/* change password with an emailed OTP (set SMTP_* variables; otherwise the code prints in this terminal) */
const otps = {};
app.post('/api/password/otp', auth, async (req, res) => {
  const code = String(crypto.randomInt(100000, 1000000));
  otps[req.user.id] = { code, exp: Date.now() + 10 * 60000, tries: 0 };
  const smtp = process.env.SMTP_HOST && nodemailer;
  try {
    if (smtp) {
      const port = Number(process.env.SMTP_PORT || 465);
      await nodemailer.createTransport({ host: process.env.SMTP_HOST, port, secure: port === 465, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } })
        .sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: req.user.email, subject: 'MYC back office password code', text: `Your code is ${code}. It expires in 10 minutes.` });
    } else console.log(`[DEV] Password code for ${req.user.email}: ${code}`);
    res.json({ sent: !!smtp, dev: !smtp });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not send the email. Check your SMTP settings.' }); }
});
app.post('/api/password/change', auth, (req, res) => {
  const o = otps[req.user.id], { otp, password } = req.body;
  if (!o || o.exp < Date.now()) return res.status(400).json({ error: 'The code expired. Request a new one.' });
  if (++o.tries > 5) { delete otps[req.user.id]; return res.status(429).json({ error: 'Too many attempts. Request a new code.' }); }
  if (otp !== o.code) return res.status(400).json({ error: 'Incorrect code.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const users = readUsers(); users.find(u => u.id === req.user.id).password = hash(password); writeUsers(users);
  delete otps[req.user.id]; res.json({ ok: true });
});

/* new-order notifications: the website posts each order here with the x-api-key header */
const orders = [];
app.post('/api/orders/webhook', (req, res) => {
  if (req.get('x-api-key') !== (process.env.ORDER_KEY || 'change-me-order-key')) return res.status(401).json({ error: 'Bad key' });
  orders.push({ id: orders.length + 1, time: Date.now(), customer: String(req.body.customer || 'A customer').slice(0, 80), total: Number(req.body.total) || 0 });
  if (orders.length > 200) orders.shift();
  res.json({ ok: true });
});
app.get('/api/orders/since/:t', auth, (req, res) => res.json(orders.filter(o => o.time > Number(req.params.t))));

app.listen(PORT, () => console.log(`MYC back office running at http://localhost:${PORT}`));