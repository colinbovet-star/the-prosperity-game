require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const cron = require('node-cron');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-please-set-JWT_SECRET-in-env';
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// ---- Database ----
const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'prosperity.db');
const fs = require('fs');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
let db;
try {
  db = new Database(DB_PATH);
} catch (err) {
  console.error('Failed to open database:', err.message);
  process.exit(1);
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS magic_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token      TEXT    NOT NULL UNIQUE,
    expires_at TEXT    NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS user_settings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL UNIQUE REFERENCES users(id),
    game_mode           TEXT    NOT NULL DEFAULT 'doubling',
    start_amount        REAL    NOT NULL DEFAULT 1000,
    start_date          TEXT    NOT NULL DEFAULT (date('now')),
    custom_type         TEXT    DEFAULT 'add',
    custom_step         REAL    DEFAULT NULL,
    reminder_email      TEXT    DEFAULT NULL,
    reminder_time       TEXT    DEFAULT '08:00',
    last_reminder_sent  TEXT    DEFAULT NULL
  );

  CREATE TABLE IF NOT EXISTS user_entries (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id),
    day_number     INTEGER NOT NULL,
    amount         REAL    NOT NULL,
    spending_notes TEXT    DEFAULT '',
    spending_items TEXT    DEFAULT '[]',
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, day_number)
  );
`);

app.use(express.json());
app.use(express.static(__dirname));

// ---- Auth middleware ----
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.userId    = payload.userId;
    req.userEmail = payload.email;
    next();
  } catch (_) {
    res.status(401).json({ error: 'Token expired or invalid' });
  }
}

// ---- Auth: request magic link ----
app.post('/api/auth/request-link', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }

  // Upsert user
  db.prepare('INSERT OR IGNORE INTO users (email) VALUES (?)').run(email);
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  // Create token (expires in 15 min)
  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO magic_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, expiresAt);

  if (!resend) return res.status(500).json({ error: 'Email not configured (missing RESEND_API_KEY)' });
  try {
    await resend.emails.send({
      from: `Prosperity Game <hello@the-prosperity-game.com>`,
      to:   email,
      subject: 'Your magic link to Prosperity Game ✨',
      html: buildMagicLinkEmail(token, email),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Magic link send error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---- Auth: verify token, issue JWT ----
app.post('/api/auth/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });

  const row = db.prepare('SELECT * FROM magic_tokens WHERE token = ?').get(token);
  if (!row)         return res.status(400).json({ error: 'Invalid link' });
  if (row.used)     return res.status(400).json({ error: 'Link already used' });
  if (new Date(row.expires_at) < new Date()) {
    return res.status(400).json({ error: 'Link expired — please request a new one' });
  }

  db.prepare('UPDATE magic_tokens SET used = 1 WHERE id = ?').run(row.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);

  const jwtToken = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ jwt: jwtToken, email: user.email });
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ userId: req.userId, email: req.userEmail });
});

// ---- Settings ----
app.get('/api/settings', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(req.userId);
  res.json(row || null);
});

app.post('/api/settings', requireAuth, (req, res) => {
  const { game_mode, start_amount, start_date, custom_type, custom_step, reminder_email, reminder_time } = req.body;
  db.prepare(`
    INSERT INTO user_settings (user_id, game_mode, start_amount, start_date, custom_type, custom_step, reminder_email, reminder_time)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      game_mode      = excluded.game_mode,
      start_amount   = excluded.start_amount,
      start_date     = excluded.start_date,
      custom_type    = excluded.custom_type,
      custom_step    = excluded.custom_step,
      reminder_email = excluded.reminder_email,
      reminder_time  = excluded.reminder_time
  `).run(
    req.userId, game_mode, start_amount, start_date,
    custom_type ?? 'add', custom_step ?? null,
    reminder_email ?? null, reminder_time ?? '08:00'
  );
  res.json({ ok: true });
});

// ---- Entries ----
app.get('/api/entries', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM user_entries WHERE user_id = ? ORDER BY day_number ASC').all(req.userId);
  res.json(rows);
});

app.get('/api/entries/:day', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM user_entries WHERE user_id = ? AND day_number = ?').get(req.userId, req.params.day);
  res.json(row || null);
});

app.post('/api/entries', requireAuth, (req, res) => {
  const { day_number, amount, spending_notes, spending_items } = req.body;
  db.prepare(`
    INSERT INTO user_entries (user_id, day_number, amount, spending_notes, spending_items)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id, day_number) DO UPDATE SET
      amount         = excluded.amount,
      spending_notes = excluded.spending_notes,
      spending_items = excluded.spending_items
  `).run(req.userId, day_number, amount, spending_notes ?? '', JSON.stringify(spending_items ?? []));
  const row = db.prepare('SELECT * FROM user_entries WHERE user_id = ? AND day_number = ?').get(req.userId, day_number);
  res.json(row);
});

// ---- Link preview (no auth — utility endpoint) ----
app.get('/api/link-preview', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url required' });
  let parsedUrl;
  try { parsedUrl = new URL(url); } catch (_) { return res.status(400).json({ error: 'Invalid URL' }); }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 7000);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
      }
    });
    clearTimeout(timer);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let html = '';
    while (html.length < 120000) {
      const { done, value } = await reader.read();
      if (done) break;
      html += decoder.decode(value, { stream: true });
    }
    reader.cancel().catch(() => {});
    const title       = extractMeta(html, 'og:title') || extractTitle(html) || '';
    const description = extractMeta(html, 'og:description') || extractMeta(html, 'description') || '';
    let image         = extractMeta(html, 'og:image') || '';
    if (image && !image.startsWith('http')) {
      try { image = new URL(image, url).href; } catch (_) { image = ''; }
    }
    const siteName = extractMeta(html, 'og:site_name') || parsedUrl.hostname || '';
    res.json({ title, description, image, siteName });
  } catch (err) {
    clearTimeout(timer);
    res.status(500).json({ error: err.message });
  }
});

// ---- Send test email ----
app.post('/api/send-test-email', requireAuth, async (req, res) => {
  const s = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(req.userId);
  if (!s?.reminder_email) {
    return res.status(400).json({ error: 'No reminder email set in settings.' });
  }
  const dayNum = calcDayNumber(s);
  const amount = calcDepositAmount(s, dayNum);
  try {
    const result = await sendReminderEmail(s.reminder_email, dayNum, amount);
    res.json({ ok: true, id: result.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Reset (user-scoped) ----
app.delete('/api/reset', requireAuth, (req, res) => {
  db.prepare('DELETE FROM user_settings WHERE user_id = ?').run(req.userId);
  db.prepare('DELETE FROM user_entries WHERE user_id = ?').run(req.userId);
  res.json({ ok: true });
});

// ---- HTML helpers ----
function extractMeta(html, prop) {
  const patterns = [
    new RegExp(`<meta[^>]+property=["']${prop}["'][^>]+content=["']([^"'<]+)["']`, 'i'),
    new RegExp(`<meta[^>]+content=["']([^"'<]+)["'][^>]+property=["']${prop}["']`, 'i'),
    new RegExp(`<meta[^>]+name=["']${prop}["'][^>]+content=["']([^"'<]+)["']`, 'i'),
    new RegExp(`<meta[^>]+content=["']([^"'<]+)["'][^>]+name=["']${prop}["']`, 'i'),
  ];
  for (const p of patterns) { const m = html.match(p); if (m) return m[1].trim(); }
  return null;
}

function extractTitle(html) {
  const m = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return m ? m[1].trim() : null;
}

// ---- Day / amount calculation ----
function calcDayNumber(s) {
  const start = new Date(s.start_date + 'T00:00:00');
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Math.floor((today - start) / 86400000) + 1;
}

function calcDepositAmount(s, dayNum) {
  if (dayNum < 1) return 0;
  const start = Number(s.start_amount);
  if (s.game_mode === 'doubling') return start * Math.pow(2, dayNum - 1);
  if (s.game_mode === 'linear')   return start * dayNum;
  const step = Number(s.custom_step) || start;
  if (s.custom_type === 'multiply') return start * Math.pow(step, dayNum - 1);
  return start + step * (dayNum - 1);
}

// ---- Email templates ----
function buildMagicLinkEmail(token, email) {
  const url = `${BASE_URL}?token=${token}`;
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#fdf8ee;font-family:Georgia,serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#fdf8ee;padding:40px 20px;">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(180,130,30,0.12);">
        <tr>
          <td style="background:linear-gradient(135deg,#c8952a,#e6b84a);padding:32px 40px;text-align:center;">
            <div style="font-size:28px;margin-bottom:6px;">✨</div>
            <div style="font-size:22px;font-weight:bold;color:#fff;letter-spacing:-0.5px;">Prosperity Game</div>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px;text-align:center;">
            <p style="margin:0 0 6px;font-size:17px;color:#3a2a0a;font-weight:bold;">Your magic link is ready</p>
            <p style="margin:0 0 28px;font-size:14px;color:#888;line-height:1.6;">
              Click the button below to sign in as <strong>${email}</strong>.<br>
              This link expires in 15 minutes and can only be used once.
            </p>
            <a href="${url}"
               style="display:inline-block;background:linear-gradient(135deg,#c8952a,#e6b84a);color:#fff;text-decoration:none;padding:14px 36px;border-radius:30px;font-size:15px;font-weight:bold;letter-spacing:0.03em;">
              Sign in to Prosperity Game →
            </a>
            <p style="margin:28px 0 0;font-size:12px;color:#bbb;">
              If you didn't request this, you can safely ignore this email.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 40px;text-align:center;border-top:1px solid #f0e8d0;">
            <p style="margin:0;font-size:11px;color:#ccc;">
              Or copy this link: <span style="color:#c8952a">${url}</span>
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

function buildReminderEmailHtml(dayNum, formatted) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#fdf8ee;font-family:Georgia,serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#fdf8ee;padding:40px 20px;">
    <tr><td align="center">
      <table width="540" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(180,130,30,0.12);">
        <tr>
          <td style="background:linear-gradient(135deg,#c8952a,#e6b84a);padding:36px 40px;text-align:center;">
            <div style="font-size:13px;color:rgba(255,255,255,0.85);letter-spacing:0.12em;text-transform:uppercase;margin-bottom:8px;">Prosperity Game</div>
            <div style="font-size:42px;font-weight:bold;color:#fff;letter-spacing:-1px;">Day ${dayNum}</div>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px;text-align:center;">
            <p style="margin:0 0 8px;font-size:16px;color:#8a6030;">Today's deposit is ready</p>
            <div style="font-size:52px;font-weight:bold;color:#c8952a;letter-spacing:-1px;line-height:1.1;">${formatted}</div>
            <p style="margin:20px 0 28px;font-size:15px;color:#666;line-height:1.6;max-width:380px;margin-left:auto;margin-right:auto;">
              The Universe has deposited ${formatted} into your account today. Spend it all with joy — imagination has no limits.
            </p>
            <a href="${BASE_URL}"
               style="display:inline-block;background:linear-gradient(135deg,#c8952a,#e6b84a);color:#fff;text-decoration:none;padding:14px 36px;border-radius:30px;font-size:15px;font-weight:bold;letter-spacing:0.03em;">
              Spend Your Prosperity ✨
            </a>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 40px;text-align:center;border-top:1px solid #f0e8d0;">
            <p style="margin:0;font-size:12px;color:#bbb;font-style:italic;">
              "Your life will simply be as good as you allow it to be." — Abraham-Hicks
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

async function sendReminderEmail(to, dayNum, amount) {
  if (!resend) throw new Error('Email not configured (missing RESEND_API_KEY)');
  const formatted = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(amount);
  const { data, error } = await resend.emails.send({
    from: 'Prosperity Game <hello@the-prosperity-game.com>',
    to,
    subject: `Day ${dayNum} — Your ${formatted} is waiting 💛`,
    html: buildReminderEmailHtml(dayNum, formatted),
  });
  if (error) throw new Error(error.message);
  return data;
}

// ---- Cron: daily reminders ----
cron.schedule('* * * * *', () => {
  const now = new Date();
  const hh  = String(now.getHours()).padStart(2, '0');
  const mm  = String(now.getMinutes()).padStart(2, '0');
  const currentTime = `${hh}:${mm}`;
  const todayStr    = now.toISOString().slice(0, 10);

  const allSettings = db.prepare(
    'SELECT * FROM user_settings WHERE reminder_email IS NOT NULL AND reminder_time IS NOT NULL'
  ).all();

  for (const s of allSettings) {
    if (s.reminder_time !== currentTime)     continue;
    if (s.last_reminder_sent === todayStr)   continue;
    const dayNum = calcDayNumber(s);
    if (dayNum < 1) continue;
    const amount = calcDepositAmount(s, dayNum);
    sendReminderEmail(s.reminder_email, dayNum, amount)
      .then(() => {
        db.prepare('UPDATE user_settings SET last_reminder_sent = ? WHERE id = ?').run(todayStr, s.id);
        console.log(`Reminder sent to ${s.reminder_email} for Day ${dayNum}`);
      })
      .catch(err => console.error(`Reminder failed for ${s.reminder_email}:`, err.message));
  }
});

app.listen(PORT, () => {
  console.log(`Prosperity Game running at http://localhost:${PORT}`);
});
