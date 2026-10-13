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
app.use(express.json());
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
const publicUser = u => ({ id: u.id, name: u.name, email: u.email });

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
app.post('/api/suppliers', auth, (req, res) => {
  const s = { name: String(req.body.name || '').slice(0, 80), loc: String(req.body.loc || '').slice(0, 80), status: 'Pending', last: '-' };
  if (!s.name) return res.status(400).json({ error: 'Enter a supplier name.' });
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

app.listen(PORT, () => console.log(`MYC back office running at http://localhost:${PORT}`));