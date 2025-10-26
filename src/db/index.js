const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const dbFilePath = path.join(__dirname, 'library.sqlite');
const db = new Database(dbFilePath);

function runMigrations() {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role TEXT NOT NULL CHECK(role IN ('student','staff','teacher','admin')),
      usn TEXT,
      name TEXT,
      password_hash TEXT NOT NULL,
      password_must_change INTEGER NOT NULL DEFAULT 0,
      UNIQUE(usn) ON CONFLICT IGNORE,
      UNIQUE(name, role) ON CONFLICT IGNORE
    );

    CREATE TABLE IF NOT EXISTS books (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      author TEXT NOT NULL,
      type TEXT,
      total_count INTEGER NOT NULL DEFAULT 1,
      cover_url TEXT,
      soft_copy_url TEXT,
      rack TEXT,
      position TEXT
    );

    CREATE TABLE IF NOT EXISTS reservations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      book_id INTEGER NOT NULL REFERENCES books(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK(status IN ('reserved','collected','cancelled','returned')),
      reserved_at TEXT NOT NULL,
      expires_at TEXT,
      collected_at TEXT,
      due_at TEXT,
      returned_at TEXT,
      fine_cents INTEGER DEFAULT 0
    );
  `);

  // Try to add password_must_change if migrating from older schema
  try {
    db.exec("ALTER TABLE users ADD COLUMN password_must_change INTEGER NOT NULL DEFAULT 0");
  } catch (e) {
    // ignore if already exists
  }
  try {
    db.exec("ALTER TABLE books ADD COLUMN cover_url TEXT");
  } catch (e) {
    // ignore if already exists
  }
}

function seedIfEmpty() {
  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount === 0) {
    const hash = (pwd) => bcrypt.hashSync(pwd, 10);
    const insertUser = db.prepare(
      'INSERT INTO users (role, usn, name, password_hash, password_must_change) VALUES (@role, @usn, @name, @password_hash, @password_must_change)'
    );
    const users = [
      { role: 'student', usn: '1RV21CS001', name: 'Student One', password_hash: hash('1RV21CS001'), password_must_change: 1 },
      { role: 'student', usn: '1RV21CS002', name: 'Student Two', password_hash: hash('1RV21CS002'), password_must_change: 1 },
      { role: 'teacher', usn: null, name: 'Alice', password_hash: hash('Alice'), password_must_change: 1 },
      { role: 'staff', usn: null, name: 'Librarian', password_hash: hash('Librarian'), password_must_change: 1 },
      { role: 'admin', usn: null, name: 'Admin', password_hash: hash('Admin'), password_must_change: 1 }
    ];
    const tx = db.transaction((rows) => {
      for (const row of rows) insertUser.run(row);
    });
    tx(users);
  }

  const bookCount = db.prepare('SELECT COUNT(*) AS c FROM books').get().c;
  if (bookCount === 0) {
    const insertBook = db.prepare(
      `INSERT INTO books (title, author, type, total_count, cover_url, soft_copy_url, rack, position)
       VALUES (@title, @author, @type, @total_count, @cover_url, @soft_copy_url, @rack, @position)`
    );
    const books = [
      { title: 'Think Python (3rd Edition)', author: 'Allen B. Downey', type: 'CS', total_count: 4, cover_url: 'https://covers.openlibrary.org/b/isbn/9781098153711-L.jpg', soft_copy_url: null, rack: 'T', position: 'T1' },
      { title: 'Clean Code', author: 'Robert C. Martin', type: 'CS', total_count: 5, cover_url: 'https://covers.openlibrary.org/b/isbn/9780132350884-L.jpg', soft_copy_url: null, rack: 'A', position: 'A3' },
      { title: 'Introduction to Algorithms', author: 'CLRS', type: 'CS', total_count: 3, cover_url: 'https://covers.openlibrary.org/b/isbn/9780262046305-L.jpg', soft_copy_url: null, rack: 'B', position: 'B1' },
      { title: 'The Pragmatic Programmer', author: 'Andrew Hunt', type: 'CS', total_count: 2, cover_url: 'https://covers.openlibrary.org/b/isbn/9780201616224-L.jpg', soft_copy_url: 'https://example.com/pragmatic.pdf', rack: 'A', position: 'A1' }
    ];
    const tx = db.transaction((rows) => {
      for (const row of rows) insertBook.run(row);
    });
    tx(books);
  }
}

function ensurePresetUsers() {
  const presets = [
    { role: 'admin', name: 'Bhumika', password: '4al23cs030' },
    { role: 'admin', name: 'Bindushree', password: '4al23cs031' },
    { role: 'admin', name: 'Chaithanya', password: '4al23cs032' },
    { role: 'admin', name: 'Chandushree', password: '4al23cs033' }
  ];
  const getByNameRole = db.prepare('SELECT id FROM users WHERE name = ? COLLATE NOCASE AND role = ?');
  const insertUser = db.prepare(
    'INSERT INTO users (role, usn, name, password_hash, password_must_change) VALUES (?,?,?,?,0)'
  );
  const updatePwd = db.prepare('UPDATE users SET password_hash=?, password_must_change=0 WHERE id=?');
  const tx = db.transaction((rows) => {
    for (const p of rows) {
      const row = getByNameRole.get(p.name, p.role);
      const hash = bcrypt.hashSync(p.password, 10);
      if (!row) {
        insertUser.run(p.role, null, p.name, hash);
      } else {
        updatePwd.run(hash, row.id);
      }
    }
  });
  tx(presets);
}

runMigrations();
seedIfEmpty();
ensurePresetUsers();

module.exports = { db };


