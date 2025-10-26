const path = require('path');
const express = require('express');
const session = require('cookie-session');
const dayjs = require('dayjs');
const bcrypt = require('bcryptjs');
const { db } = require('./db');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    name: 'libsess',
    keys: ['a_secure_key_change_me'],
    maxAge: 24 * 60 * 60 * 1000
  })
);

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => res.redirect('/catalog'));

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Simple diagnostics to verify the running server has latest code
app.get('/__ping', (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString(), version: 'admin-actions-v3' });
});

app.post('/login', (req, res) => {
  const { role, usn, name, password } = req.body;
  const identifier = (role === 'student' ? (usn || '') : (name || '')).trim();
  const identifierLower = identifier.toLowerCase();
  let user;
  if (role === 'student') {
    user = db.prepare("SELECT * FROM users WHERE role=? AND usn = ? COLLATE NOCASE").get('student', identifier);
  } else {
    const allowed = ['staff', 'teacher', 'admin'];
    if (!allowed.includes(role)) return res.render('login', { error: 'Invalid role' });
    user = db.prepare("SELECT * FROM users WHERE role=? AND name = ? COLLATE NOCASE").get(role, identifier);
  }
  // Auto-provision users (except admin) so anybody can log in the first time
  if (!user && role === 'student' && identifier) {
    const hash = bcrypt.hashSync('', 10);
    const info = db.prepare('INSERT INTO users (role, usn, name, password_hash, password_must_change) VALUES (?,?,?,?,1)')
      .run('student', identifier, null, hash);
    user = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  } else if (!user && (role === 'teacher' || role === 'staff') && identifier) {
    const hash = bcrypt.hashSync('', 10);
    const info = db.prepare('INSERT INTO users (role, usn, name, password_hash, password_must_change) VALUES (?,?,?,?,1)')
      .run(role, null, identifier, hash);
    user = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  }
  if (!user) return res.render('login', { error: 'User not found' });
  // First-time login: password must equal username/USN (case-insensitive)
  if (user.password_must_change) {
    const pass = (password || '').trim().toLowerCase();
    if (pass !== identifierLower) {
      return res.render('login', { error: 'For first login, use your username as the password' });
    }
    req.session.user = { id: user.id, role: user.role, usn: user.usn, name: user.name };
    return res.redirect('/password');
  }
  const ok = bcrypt.compareSync(password || '', user.password_hash);
  if (!ok) return res.render('login', { error: 'Invalid credentials' });
  req.session.user = { id: user.id, role: user.role, usn: user.usn, name: user.name };
  // Force password change if flagged
  try {
    if (user.password_must_change) return res.redirect('/password');
  } catch (e) { /* older DB without column */ }
  res.redirect('/catalog');
});

app.post('/logout', (req, res) => {
  req.session = null;
  res.redirect('/login');
});

app.get('/password', requireAuth, (req, res) => {
  res.render('password', { user: req.session.user, error: null, success: null });
});

app.post('/password', requireAuth, (req, res) => {
  const { current_password, new_password, confirm_password } = req.body;
  if (!new_password || new_password.length < 6) {
    return res.render('password', { user: req.session.user, error: 'Password must be at least 6 characters', success: null });
  }
  if (new_password !== confirm_password) {
    return res.render('password', { user: req.session.user, error: 'Passwords do not match', success: null });
  }
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if (!u) return res.redirect('/login');
  // If user must change password, don't require current password
  if (!u.password_must_change) {
    if (!bcrypt.compareSync(current_password || '', u.password_hash)) {
      return res.render('password', { user: req.session.user, error: 'Current password is incorrect', success: null });
    }
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE users SET password_hash=?, password_must_change=0 WHERE id=?').run(hash, u.id);
  return res.render('password', { user: req.session.user, error: null, success: 'Password updated successfully' });
});

app.get('/catalog', requireAuth, (req, res) => {
  // Clean up any expired holds for this user so UI reflects current state
  const nowIso = dayjs().toISOString();
  db.prepare(
    `UPDATE reservations 
     SET status='cancelled' 
     WHERE user_id=? AND status='reserved' AND expires_at IS NOT NULL AND expires_at < ?`
  ).run(req.session.user.id, nowIso);
  const books = db.prepare(`
    SELECT b.*, 
      b.total_count - (
        SELECT COUNT(*) FROM reservations r 
        WHERE r.book_id = b.id AND r.status IN ('reserved','collected')
      ) AS available_count,
      (
        SELECT COUNT(*) FROM reservations r 
        WHERE r.book_id = b.id AND r.status IN ('reserved','collected')
      ) AS currently_booked
    FROM books b
    ORDER BY b.title ASC
  `).all();
  res.render('catalog', { user: req.session.user, books });
});

app.post('/reserve/:bookId', requireAuth, (req, res) => {
  const user = req.session.user;
  const bookId = Number(req.params.bookId);
  const book = db.prepare('SELECT * FROM books WHERE id=?').get(bookId);
  if (!book) return res.status(404).send('Book not found');

  // Auto-cancel any expired reservations for this user (including this book)
  const nowIso = dayjs().toISOString();
  db.prepare(
    `UPDATE reservations 
     SET status='cancelled' 
     WHERE user_id=? AND status='reserved' AND expires_at IS NOT NULL AND expires_at < ?`
  ).run(user.id, nowIso);

  // Disallow reserving the same book twice (only if still active)
  const alreadyRow = db.prepare(
    `SELECT id, status, reserved_at, collected_at FROM reservations WHERE user_id=? AND book_id=? AND status IN ('reserved','collected')`
  ).get(user.id, bookId);
  if (alreadyRow) {
    return res.status(400).render('message', {
      user,
      title: 'Already Reserved',
      message: `You already have this book ${alreadyRow.status}. Please cancel/return it first.`,
      imageUrl: '/img/reservealredy.jpeg'
    });
  }

  const activeCount = db.prepare(
    `SELECT COUNT(*) AS c FROM reservations WHERE user_id=? AND status IN ('reserved','collected')`
  ).get(user.id).c;
  if (activeCount >= 2) return res.status(400).send('Limit reached: 2 active books total');

  const sameTypeActive = db.prepare(
    `SELECT COUNT(*) AS c FROM reservations r JOIN books b ON b.id=r.book_id
     WHERE r.user_id=? AND r.status IN ('reserved','collected') AND b.type=(SELECT type FROM books WHERE id=?)`
  ).get(user.id, bookId).c;
  if (sameTypeActive >= 1) return res.status(400).send('Only one book per type allowed');

  const available = db.prepare(`
    SELECT (b.total_count - (
      SELECT COUNT(*) FROM reservations r WHERE r.book_id=b.id AND r.status IN ('reserved','collected')
    )) AS available FROM books b WHERE b.id=?
  `).get(bookId).available;
  if (available <= 0) return res.status(400).send('No copies available');

  const now = dayjs();
  const expiresAt = now.add(12, 'hour');
  db.prepare(
    `INSERT INTO reservations (user_id, book_id, status, reserved_at, expires_at)
     VALUES (?,?,?,?,?)`
  ).run(user.id, bookId, 'reserved', now.toISOString(), expiresAt.toISOString());

  res.redirect('/catalog');
});

// Collect is restricted to staff/admin via admin routes. Users cannot call this directly.
app.post('/collect/:reservationId', requireAuth, (req, res) => {
  const { reservationId } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(reservationId);
  if (!r || r.user_id !== req.session.user.id) return res.status(404).send('Not found');
  if (!['admin','staff'].includes(req.session.user.role)) return res.status(403).send('Only staff/admin can mark collected');
  if (r.status !== 'reserved') return res.status(400).send('Not in reserved state');
  if (r.expires_at && dayjs().isAfter(dayjs(r.expires_at))) {
    db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(reservationId);
    return res.status(400).send('Reservation expired');
  }
  const now = dayjs();
  const due = now.add(15, 'day');
  db.prepare("UPDATE reservations SET status='collected', collected_at=?, due_at=? WHERE id=?")
    .run(now.toISOString(), due.toISOString(), reservationId);
  res.redirect('/me');
});

app.post('/cancel/:reservationId', requireAuth, (req, res) => {
  const { reservationId } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(reservationId);
  if (!r || r.user_id !== req.session.user.id) return res.status(404).send('Not found');
  if (!['reserved','collected'].includes(r.status)) return res.status(400).send('Cannot cancel');
  db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(reservationId);
  res.redirect('/me');
});

app.get('/me', requireAuth, (req, res) => {
  const user = req.session.user;
  const reservations = db.prepare(
    `SELECT r.*, b.title, b.author FROM reservations r JOIN books b ON b.id=r.book_id
     WHERE r.user_id=? ORDER BY r.reserved_at DESC`
  ).all(user.id);

  // compute fines dynamically: 1 unit/day after due
  const now = dayjs();
  const rows = reservations.map((r) => {
    let fine = 0;
    if (r.status === 'collected' && r.due_at && now.isAfter(dayjs(r.due_at))) {
      const daysLate = now.diff(dayjs(r.due_at), 'day');
      fine = Math.max(0, daysLate) * 10; // 10 currency units per day
    }
    return { ...r, fine };
  });
  res.render('me', { user, reservations: rows });
});

// Admin simple views
function requireAdmin(req, res, next) {
  if (!req.session.user || !['admin','staff'].includes(req.session.user.role)) {
    return res.status(403).send('Forbidden');
  }
  next();
}

app.get('/admin', requireAdmin, (req, res) => {
  const reservations = db.prepare(
    `SELECT r.*, b.title, u.name, u.usn FROM reservations r
     JOIN books b ON b.id=r.book_id
     JOIN users u ON u.id=r.user_id
     ORDER BY r.reserved_at DESC`
  ).all();
  const books = db.prepare('SELECT * FROM books ORDER BY title ASC').all();
  res.render('admin', { user: req.session.user, reservations, books, error: null });
});

app.post('/admin/books/update', requireAdmin, (req, res) => {
  const { bookId, total_count, cover_url, soft_copy_url, rack, position } = req.body;
  const id = Number(bookId);
  const n = Number(total_count);
  if (!Number.isInteger(id) || !Number.isInteger(n) || n < 0) {
    return res.status(400).send('Invalid input');
  }
  db.prepare('UPDATE books SET total_count=?, cover_url=?, soft_copy_url=?, rack=?, position=? WHERE id=?')
    .run(n, (cover_url || null), (soft_copy_url || null), (rack || null), (position || null), id);
  res.redirect('/admin');
});

// Admin reservation management
app.post('/admin/reservations/:id/cancel', requireAdmin, (req, res) => {
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (!['reserved','collected'].includes(r.status)) return res.status(400).send('Cannot cancel');
  db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(id);
  res.redirect('/admin');
});

// Also support GET to avoid method mismatch from some clients
app.get('/admin/reservations/:id/cancel', requireAdmin, (req, res) => {
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (!['reserved','collected'].includes(r.status)) return res.status(400).send('Cannot cancel');
  db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(id);
  res.redirect('/admin');
});

// Accept any HTTP method for robustness
app.all('/admin/reservations/:id/cancel', requireAdmin, (req, res) => {
  console.log('[ADMIN] cancel', { id: req.params.id, method: req.method });
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (!['reserved','collected'].includes(r.status)) return res.status(400).send('Cannot cancel');
  db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(id);
  res.redirect('/admin');
});

app.post('/admin/reservations/:id/collect', requireAdmin, (req, res) => {
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (r.status !== 'reserved') return res.status(400).send('Not in reserved state');
  if (r.expires_at && dayjs().isAfter(dayjs(r.expires_at))) {
    db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(id);
    return res.status(400).send('Reservation expired');
  }
  const now = dayjs();
  const due = now.add(15, 'day');
  db.prepare("UPDATE reservations SET status='collected', collected_at=?, due_at=? WHERE id=?")
    .run(now.toISOString(), due.toISOString(), id);
  res.redirect('/admin');
});

app.get('/admin/reservations/:id/collect', requireAdmin, (req, res) => {
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (r.status !== 'reserved') return res.status(400).send('Not in reserved state');
  if (r.expires_at && dayjs().isAfter(dayjs(r.expires_at))) {
    db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(id);
    return res.status(400).send('Reservation expired');
  }
  const now = dayjs();
  const due = now.add(15, 'day');
  db.prepare("UPDATE reservations SET status='collected', collected_at=?, due_at=? WHERE id=?")
    .run(now.toISOString(), due.toISOString(), id);
  res.redirect('/admin');
});

app.all('/admin/reservations/:id/collect', requireAdmin, (req, res) => {
  console.log('[ADMIN] collect', { id: req.params.id, method: req.method });
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (r.status !== 'reserved') return res.status(400).send('Not in reserved state');
  if (r.expires_at && dayjs().isAfter(dayjs(r.expires_at))) {
    db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(id);
    return res.status(400).send('Reservation expired');
  }
  const now = dayjs();
  const due = now.add(15, 'day');
  db.prepare("UPDATE reservations SET status='collected', collected_at=?, due_at=? WHERE id=?")
    .run(now.toISOString(), due.toISOString(), id);
  res.redirect('/admin');
});

app.post('/admin/reservations/:id/return', requireAdmin, (req, res) => {
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (r.status !== 'collected') return res.status(400).send('Only collected items can be returned');
  const now = dayjs();
  db.prepare("UPDATE reservations SET status='returned', returned_at=? WHERE id=?")
    .run(now.toISOString(), id);
  res.redirect('/admin');
});

app.get('/admin/reservations/:id/return', requireAdmin, (req, res) => {
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (r.status !== 'collected') return res.status(400).send('Only collected items can be returned');
  const now = dayjs();
  db.prepare("UPDATE reservations SET status='returned', returned_at=? WHERE id=?")
    .run(now.toISOString(), id);
  res.redirect('/admin');
});

app.all('/admin/reservations/:id/return', requireAdmin, (req, res) => {
  console.log('[ADMIN] return', { id: req.params.id, method: req.method });
  const { id } = req.params;
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  if (r.status !== 'collected') return res.status(400).send('Only collected items can be returned');
  const now = dayjs();
  db.prepare("UPDATE reservations SET status='returned', returned_at=? WHERE id=?")
    .run(now.toISOString(), id);
  res.redirect('/admin');
});

// Generic action handler (catch-all) to prevent 404s due to method/path variations
app.all('/admin/reservations/:id/:action', requireAdmin, (req, res, next) => {
  console.log('[ADMIN] generic action', { id: req.params.id, action: req.params.action, method: req.method });
  const { id, action } = req.params;
  if (!['collect','cancel','return'].includes(action)) return next();
  const r = db.prepare('SELECT * FROM reservations WHERE id=?').get(id);
  if (!r) return res.status(404).send('Not found');
  const now = dayjs();
  if (action === 'cancel') {
    if (!['reserved','collected'].includes(r.status)) return res.status(400).send('Cannot cancel');
    db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(id);
    return res.redirect('/admin');
  }
  if (action === 'collect') {
    if (r.status !== 'reserved') return res.status(400).send('Not in reserved state');
    if (r.expires_at && dayjs().isAfter(dayjs(r.expires_at))) {
      db.prepare("UPDATE reservations SET status='cancelled' WHERE id=?").run(id);
      return res.status(400).send('Reservation expired');
    }
    const due = now.add(15, 'day');
    db.prepare("UPDATE reservations SET status='collected', collected_at=?, due_at=? WHERE id=?")
      .run(now.toISOString(), due.toISOString(), id);
    return res.redirect('/admin');
  }
  if (action === 'return') {
    if (r.status !== 'collected') return res.status(400).send('Only collected items can be returned');
    db.prepare("UPDATE reservations SET status='returned', returned_at=? WHERE id=?")
      .run(now.toISOString(), id);
    return res.redirect('/admin');
  }
  next();
});
// Auto-expire route (can be hit by a cron)
app.post('/tasks/expire', (req, res) => {
  const now = dayjs().toISOString();
  const result = db.prepare(
    `UPDATE reservations SET status='cancelled' 
     WHERE status='reserved' AND expires_at IS NOT NULL AND expires_at < ?`
  ).run(now);
  res.json({ expired: result.changes });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});


