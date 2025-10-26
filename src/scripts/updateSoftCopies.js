const { db } = require('../db');

const updates = [
  {
    title: 'Think Python (3rd Edition)',
    url: 'https://greenteapress.com/thinkpython3/thinkpython3.pdf'
  }
];

for (const u of updates) {
  const res = db
    .prepare('UPDATE books SET soft_copy_url=? WHERE title=?')
    .run(u.url, u.title);
  console.log(`Updated ${u.title}: ${res.changes} row(s)`);
}

console.log('Soft copy URLs updated.');








