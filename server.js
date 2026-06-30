require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files (index.html, admin.html)
const path = require('path');
app.use(express.static(path.join(__dirname)));

// Multer for image upload (memory storage)
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// DB Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) { console.log('DB Error:', err); return; }
  console.log('MySQL Connected!');
  // Increase GROUP_CONCAT limit for large image data
  db.query("SET SESSION group_concat_max_len = 1000000000", (err) => {
    if (err) console.log('Warning:', err);
  });
  createDefaultAdmin();
});

// Create default admin if not exists
function createDefaultAdmin() {
  db.query('SELECT * FROM admin_users WHERE username = ?', ['admin'], (err, results) => {
    if (results && results.length === 0) {
      const hashed = bcrypt.hashSync('viki@123', 10);
      db.query('INSERT INTO admin_users (username, password) VALUES (?, ?)', ['admin', hashed]);
      console.log('Default admin created — username: admin, password: viki@123');
    }
  });
}

// ── AUTH MIDDLEWARE ──────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── ADMIN LOGIN ──────────────────────────────
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM admin_users WHERE username = ?', [username], (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = bcrypt.compareSync(password, results[0].password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: results[0].id, username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  });
});

// ── CATEGORIES ───────────────────────────────
// Get all categories (public)
app.get('/api/categories', (req, res) => {
  db.query('SELECT * FROM categories ORDER BY id ASC', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Add category (admin)
app.post('/api/categories', authMiddleware, (req, res) => {
  const { name, description, emoji } = req.body;
  db.query('INSERT INTO categories (name, description, emoji) VALUES (?, ?, ?)',
    [name, description, emoji], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: result.insertId, name, description, emoji });
    });
});

// Update category (admin)
app.put('/api/categories/:id', authMiddleware, (req, res) => {
  const { name, description, emoji, cover_img } = req.body;
  db.query('UPDATE categories SET name=?, description=?, emoji=?, cover_img=? WHERE id=?',
    [name, description, emoji, cover_img || null, req.params.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
});

// Delete category (admin)
app.delete('/api/categories/:id', authMiddleware, (req, res) => {
  db.query('DELETE FROM categories WHERE id=?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ── PRODUCTS ─────────────────────────────────
// Get products by category (public)
app.get('/api/products/:categoryId', (req, res) => {
  const sql = `
    SELECT p.*, GROUP_CONCAT(pi.image_data ORDER BY pi.sort_order SEPARATOR '|||') as images
    FROM products p
    LEFT JOIN product_images pi ON p.id = pi.product_id
    WHERE p.category_id = ?
    GROUP BY p.id
    ORDER BY p.created_at DESC`;
  db.query(sql, [req.params.categoryId], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    const products = results.map(p => ({
      ...p,
      images: p.images ? p.images.split('|||') : []
    }));
    res.json(products);
  });
});

// Add product (admin)
app.post('/api/products', authMiddleware, (req, res) => {
  const { category_id, title, price, sub_category, condition_type, location, phone, description, images } = req.body;
  db.query(
    'INSERT INTO products (category_id, title, price, sub_category, condition_type, location, phone, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [category_id, title, price, sub_category, condition_type, location, phone, description],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      const productId = result.insertId;
      if (images && images.length > 0) {
        const imgValues = images.slice(0, 10).map((img, i) => [productId, img, i]);
        db.query('INSERT INTO product_images (product_id, image_data, sort_order) VALUES ?', [imgValues], (err2) => {
          if (err2) return res.status(500).json({ error: err2.message });
          res.json({ id: productId, success: true });
        });
      } else {
        res.json({ id: productId, success: true });
      }
    }
  );
});

// Update product (admin)
app.put('/api/products/:id', authMiddleware, (req, res) => {
  const { title, price, sub_category, condition_type, location, phone, description, images } = req.body;
  db.query(
    'UPDATE products SET title=?, price=?, sub_category=?, condition_type=?, location=?, phone=?, description=? WHERE id=?',
    [title, price, sub_category, condition_type, location, phone, description, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      // Update images
      db.query('DELETE FROM product_images WHERE product_id=?', [req.params.id], (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });
        if (images && images.length > 0) {
          const imgValues = images.slice(0, 10).map((img, i) => [req.params.id, img, i]);
          db.query('INSERT INTO product_images (product_id, image_data, sort_order) VALUES ?', [imgValues], (err3) => {
            if (err3) return res.status(500).json({ error: err3.message });
            res.json({ success: true });
          });
        } else {
          res.json({ success: true });
        }
      });
    }
  );
});

// Mark sold (admin)
app.patch('/api/products/:id/sold', authMiddleware, (req, res) => {
  const { sold } = req.body;
  const soldAt = sold ? new Date() : null;
  db.query('UPDATE products SET sold=?, sold_at=? WHERE id=?', [sold, soldAt, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Delete product (admin)
app.delete('/api/products/:id', authMiddleware, (req, res) => {
  db.query('DELETE FROM products WHERE id=?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Sales history (admin)
app.get('/api/sales', authMiddleware, (req, res) => {
  const sql = `
    SELECT p.id, p.title, p.price, p.sold_at, p.location, p.sub_category,
           c.name as category_name, c.emoji as category_emoji
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    WHERE p.sold = 1
    ORDER BY p.sold_at DESC`;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});