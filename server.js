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
app.use(express.static(__dirname)); // serves index.html and logo.png

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

app.listen(PORT, () => console.log(`MYC back office running at http://localhost:${PORT}`));