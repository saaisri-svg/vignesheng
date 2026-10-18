require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files
app.use(express.static(__dirname));

// Multer for image upload
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

// DB Connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

console.log('MySQL Pool Created!');

// Create default admin
createDefaultAdmin();

function createDefaultAdmin() {
  db.query(
    'SELECT * FROM admin_users WHERE username = ?',
    ['admin'],
    (err, results) => {
      if (err) {
        console.error('Admin check error:', err.message);
        return;
      }

      if (results.length === 0) {
        const hashed = bcrypt.hashSync('viki@123', 10);

        db.query(
          'INSERT INTO admin_users (username, password) VALUES (?, ?)',
          ['admin', hashed],
          (insertErr) => {
            if (insertErr) {
              console.error('Admin creation error:', insertErr.message);
              return;
            }

            console.log('Default admin created — username: admin');
          }
        );
      }
    }
  );
}

// AUTH MIDDLEWARE
function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ADMIN LOGIN
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;

  db.query(
    'SELECT * FROM admin_users WHERE username = ?',
    [username],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({
          error: 'Invalid credentials'
        });
      }

      const valid = bcrypt.compareSync(
        password,
        results[0].password
      );

      if (!valid) {
        return res.status(401).json({
          error: 'Invalid credentials'
        });
      }

      const token = jwt.sign(
        {
          id: results[0].id,
          username
        },
        process.env.JWT_SECRET,
        {
          expiresIn: '7d'
        }
      );

      res.json({
        token,
        username
      });
    }
  );
});

// CATEGORIES

// Get all categories
app.get('/api/categories', (req, res) => {
  db.query(
    'SELECT * FROM categories ORDER BY id ASC',
    (err, results) => {
      if (err) {
        return res.status(500).json({
          error: err.message
        });
      }

      res.json(results);
    }
  );
});

// Add category
app.post('/api/categories', authMiddleware, (req, res) => {
  const { name, description, emoji, type } = req.body;
  const catType = type === 'service' ? 'service' : 'marketplace';

  db.query(
    'INSERT INTO categories (name, description, emoji, type) VALUES (?, ?, ?, ?)',
    [name, description, emoji, catType],
    (err, result) => {
      if (err) {
        return res.status(500).json({
          error: err.message
        });
      }

      res.json({
        id: result.insertId,
        name,
        description,
        emoji,
        type: catType
      });
    }
  );
});

// Update category
app.put('/api/categories/:id', authMiddleware, (req, res) => {
  const {
    name,
    description,
    emoji,
    cover_img,
    type
  } = req.body;
  const catType = type === 'service' ? 'service' : 'marketplace';

  db.query(
    `UPDATE categories 
     SET name=?, description=?, emoji=?, cover_img=?, type=? 
     WHERE id=?`,
    [
      name,
      description,
      emoji,
      cover_img || null,
      catType,
      req.params.id
    ],
    (err) => {
      if (err) {
        return res.status(500).json({
          error: err.message
        });
      }

      res.json({ success: true });
    }
  );
});

// Delete category
app.delete('/api/categories/:id', authMiddleware, (req, res) => {
  db.query(
    'DELETE FROM categories WHERE id=?',
    [req.params.id],
    (err) => {
      if (err) {
        return res.status(500).json({
          error: err.message
        });
      }

      res.json({ success: true });
    }
  );
});

// PRODUCTS

// Get products by category
app.get('/api/products/:categoryId', (req, res) => {
  const productSql = `
    SELECT *
    FROM products
    WHERE category_id = ?
    ORDER BY created_at DESC
  `;

  db.query(
    productSql,
    [req.params.categoryId],
    (err, products) => {
      if (err) {
        return res.status(500).json({
          error: err.message
        });
      }

      if (products.length === 0) {
        return res.json([]);
      }

      const productIds = products.map(p => p.id);

      const imageSql = `
        SELECT product_id, image_data, sort_order
        FROM product_images
        WHERE product_id IN (?)
        ORDER BY product_id, sort_order
      `;

      db.query(
        imageSql,
        [productIds],
        (err2, images) => {
          if (err2) {
            return res.status(500).json({
              error: err2.message
            });
          }

          const imageMap = {};

          images.forEach(img => {
            if (!imageMap[img.product_id]) {
              imageMap[img.product_id] = [];
            }

            imageMap[img.product_id].push(img.image_data);
          });

          let isAdmin = false;
          try {
            jwt.verify(req.headers['authorization'] || '', process.env.JWT_SECRET);
            isAdmin = true;
          } catch (e) { /* public visitor */ }

          const result = products.map(product => {
            const { cost_price, ...publicFields } = product;
            return {
              ...(isAdmin ? product : publicFields),
              images: imageMap[product.id] || []
            };
          });

          res.json(result);
        }
      );
    }
  );
});

// Add product
app.post('/api/products', authMiddleware, (req, res) => {
  const {
    category_id,
    title,
    price,
    sub_category,
    condition_type,
    location,
    phone,
    description,
    images,
    cost_price
  } = req.body;
  const cost = (cost_price === '' || cost_price === undefined || cost_price === null) ? null : Number(cost_price);

  db.query(
    `INSERT INTO products
    (
      category_id,
      title,
      price,
      sub_category,
      condition_type,
      location,
      phone,
      description,
      cost_price
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      category_id,
      title,
      price,
      sub_category,
      condition_type,
      location,
      phone,
      description,
      cost
    ],
    (err, result) => {
      if (err) {
        return res.status(500).json({
          error: err.message
        });
      }

      const productId = result.insertId;

      if (images && images.length > 0) {
        const imgValues = images
          .slice(0, 10)
          .map((img, i) => [
            productId,
            img,
            i
          ]);

        db.query(
          `INSERT INTO product_images
          (product_id, image_data, sort_order)
          VALUES ?`,
          [imgValues],
          (err2) => {
            if (err2) {
              return res.status(500).json({
                error: err2.message
              });
            }

            res.json({
              id: productId,
              success: true
            });
          }
        );
      } else {
        res.json({
          id: productId,
          success: true
        });
      }
    }
  );
});

// Update product
app.put('/api/products/:id', authMiddleware, (req, res) => {
  const {
    title,
    price,
    sub_category,
    condition_type,
    location,
    phone,
    description,
    images,
    cost_price
  } = req.body;
  const cost = (cost_price === '' || cost_price === undefined || cost_price === null) ? null : Number(cost_price);

  db.query(
    `UPDATE products
    SET
      title=?,
      price=?,
      sub_category=?,
      condition_type=?,
      location=?,
      phone=?,
      description=?,
      cost_price=?
    WHERE id=?`,
    [
      title,
      price,
      sub_category,
      condition_type,
      location,
      phone,
      description,
      cost,
      req.params.id
    ],
    (err) => {
      if (err) {
        return res.status(500).json({
          error: err.message
        });
      }

      // Delete old images
      db.query(
        'DELETE FROM product_images WHERE product_id=?',
        [req.params.id],
        (err2) => {
          if (err2) {
            return res.status(500).json({
              error: err2.message
            });
          }

          if (images && images.length > 0) {
            const imgValues = images
              .slice(0, 10)
              .map((img, i) => [
                req.params.id,
                img,
                i
              ]);

            db.query(
              `INSERT INTO product_images
              (product_id, image_data, sort_order)
              VALUES ?`,
              [imgValues],
              (err3) => {
                if (err3) {
                  return res.status(500).json({
                    error: err3.message
                  });
                }

                res.json({ success: true });
              }
            );
          } else {
            res.json({ success: true });
          }
        }
      );
    }
  );
});

// Mark product as sold
app.patch(
  '/api/products/:id/sold',
  authMiddleware,
  (req, res) => {
    const { sold } = req.body;

    const soldAt = sold
      ? new Date()
      : null;

    db.query(
      'UPDATE products SET sold=?, sold_at=? WHERE id=?',
      [
        sold,
        soldAt,
        req.params.id
      ],
      (err) => {
        if (err) {
          return res.status(500).json({
            error: err.message
          });
        }

        res.json({ success: true });
      }
    );
  }
);

// Delete product
app.delete(
  '/api/products/:id',
  authMiddleware,
  (req, res) => {
    db.query(
      'DELETE FROM products WHERE id=?',
      [req.params.id],
      (err) => {
        if (err) {
          return res.status(500).json({
            error: err.message
          });
        }

        res.json({ success: true });
      }
    );
  }
);

// Sales history
app.get('/api/sales', authMiddleware, (req, res) => {
  const sql = `
    SELECT
      p.id,
      p.title,
      p.price,
      p.sold_at,
      p.location,
      p.sub_category,
      c.name AS category_name,
      c.emoji AS category_emoji
    FROM products p
    LEFT JOIN categories c
      ON p.category_id = c.id
    WHERE p.sold = 1
    ORDER BY p.sold_at DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }

    res.json(results);
  });
});

// ---- SITE SETTINGS + GALLERY (About/Contact text, Before/After photos) ----
function initExtraTables() {
  db.query(
    `CREATE TABLE IF NOT EXISTS site_settings (
      key_name VARCHAR(50) PRIMARY KEY,
      setting_value TEXT
    )`,
    (err) => { if (err) console.error('site_settings table error:', err.message); }
  );
  db.query(
    `CREATE TABLE IF NOT EXISTS gallery (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(150),
      before_img LONGTEXT,
      after_img LONGTEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`,
    (err) => { if (err) console.error('gallery table error:', err.message); }
  );
}
initExtraTables();

// cost_price column on products (ignore error if it already exists)
db.query('ALTER TABLE products ADD COLUMN cost_price DECIMAL(12,2) NULL', (err) => {
  if (err && err.code !== 'ER_DUP_FIELDNAME') console.error('cost_price column error:', err.message);
});
db.query(
  `CREATE TABLE IF NOT EXISTS service_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category_id INT NULL,
    title VARCHAR(200),
    income DECIMAL(12,2) NOT NULL DEFAULT 0,
    expense DECIMAL(12,2) NOT NULL DEFAULT 0,
    job_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  (err) => { if (err) console.error('service_jobs table error:', err.message); }
);

const SETTING_KEYS = ['about', 'phone', 'whatsapp', 'address'];

// Get settings (public)
app.get('/api/settings', (req, res) => {
  db.query('SELECT key_name, setting_value FROM site_settings', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const out = {};
    rows.forEach(r => { out[r.key_name] = r.setting_value; });
    res.json(out);
  });
});

// Save settings (admin)
app.put('/api/settings', authMiddleware, (req, res) => {
  const rows = SETTING_KEYS
    .filter(k => typeof req.body[k] === 'string')
    .map(k => [k, req.body[k]]);
  if (!rows.length) return res.json({ success: true });
  db.query(
    `INSERT INTO site_settings (key_name, setting_value) VALUES ?
     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
    [rows],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Get gallery (public)
app.get('/api/gallery', (req, res) => {
  db.query(
    'SELECT id, title, before_img, after_img FROM gallery ORDER BY id DESC',
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// Add gallery item (admin)
app.post('/api/gallery', authMiddleware, (req, res) => {
  const { title, before_img, after_img } = req.body;
  if (!before_img || !after_img) {
    return res.status(400).json({ error: 'Before and After photos required' });
  }
  db.query(
    'INSERT INTO gallery (title, before_img, after_img) VALUES (?, ?, ?)',
    [title || '', before_img, after_img],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: result.insertId, success: true });
    }
  );
});

// Delete gallery item (admin)
app.delete('/api/gallery/:id', authMiddleware, (req, res) => {
  db.query('DELETE FROM gallery WHERE id=?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ---- SERVICE JOBS (income / expense) ----
app.get('/api/jobs', authMiddleware, (req, res) => {
  db.query(
    `SELECT j.id, j.title, j.income, j.expense, j.job_date, j.category_id, c.name AS category_name
     FROM service_jobs j LEFT JOIN categories c ON j.category_id = c.id
     ORDER BY j.job_date DESC, j.id DESC LIMIT 200`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.post('/api/jobs', authMiddleware, (req, res) => {
  const { category_id, title, income, expense, job_date } = req.body;
  db.query(
    'INSERT INTO service_jobs (category_id, title, income, expense, job_date) VALUES (?, ?, ?, ?, ?)',
    [category_id || null, title || '', Number(income) || 0, Number(expense) || 0, job_date || new Date()],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: result.insertId, success: true });
    }
  );
});

app.delete('/api/jobs/:id', authMiddleware, (req, res) => {
  db.query('DELETE FROM service_jobs WHERE id=?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ---- PROFIT / LOSS SUMMARY ----
const dbq = (sql, params) => new Promise((resolve, reject) => {
  db.query(sql, params || [], (err, rows) => (err ? reject(err) : resolve(rows)));
});

app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const now = new Date();
    const monthStart = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;

    const marketSql = (extra) => `
      SELECT
        COUNT(*) AS listed,
        COALESCE(SUM(p.sold = 0), 0) AS in_stock,
        COALESCE(SUM(p.sold = 1), 0) AS sold_count,
        COALESCE(SUM(CASE WHEN p.sold = 1 THEN p.price ELSE 0 END), 0) AS sales_total,
        COALESCE(SUM(CASE WHEN p.sold = 1 AND p.cost_price IS NOT NULL THEN p.cost_price ELSE 0 END), 0) AS cost_total,
        COALESCE(SUM(CASE WHEN p.sold = 1 AND p.cost_price IS NOT NULL THEN p.price - p.cost_price ELSE 0 END), 0) AS profit,
        COALESCE(SUM(CASE WHEN p.sold = 1 AND p.cost_price IS NULL THEN 1 ELSE 0 END), 0) AS missing_cost
      FROM products p JOIN categories c ON p.category_id = c.id
      WHERE c.type <> 'service' ${extra}`;

    const jobSql = (extra) => `
      SELECT COUNT(*) AS jobs,
        COALESCE(SUM(income), 0) AS income,
        COALESCE(SUM(expense), 0) AS expense
      FROM service_jobs WHERE 1=1 ${extra}`;

    const [mAll] = await dbq(marketSql(''));
    const [mMonth] = await dbq(marketSql('AND p.sold = 1 AND p.sold_at >= ?'), [monthStart]);
    const [sAll] = await dbq(jobSql(''));
    const [sMonth] = await dbq(jobSql('AND job_date >= ?'), [monthStart]);

    // Month-wise breakdown (newest first)
    const mMonthly = await dbq(`
      SELECT DATE_FORMAT(p.sold_at, '%Y-%m') AS ym,
        COUNT(*) AS sold_count,
        COALESCE(SUM(p.price), 0) AS sales_total,
        COALESCE(SUM(CASE WHEN p.cost_price IS NOT NULL THEN p.cost_price ELSE 0 END), 0) AS cost_total,
        COALESCE(SUM(CASE WHEN p.cost_price IS NOT NULL THEN p.price - p.cost_price ELSE 0 END), 0) AS profit,
        COALESCE(SUM(CASE WHEN p.cost_price IS NULL THEN 1 ELSE 0 END), 0) AS missing_cost
      FROM products p JOIN categories c ON p.category_id = c.id
      WHERE c.type <> 'service' AND p.sold = 1 AND p.sold_at IS NOT NULL
      GROUP BY ym ORDER BY ym DESC LIMIT 24`);
    const sMonthly = await dbq(`
      SELECT DATE_FORMAT(job_date, '%Y-%m') AS ym,
        COUNT(*) AS jobs,
        COALESCE(SUM(income), 0) AS income,
        COALESCE(SUM(expense), 0) AS expense
      FROM service_jobs WHERE job_date IS NOT NULL
      GROUP BY ym ORDER BY ym DESC LIMIT 24`);

    const num = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, Number(v)]));
    const numRow = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, k === 'ym' ? v : Number(v)]));
    res.json({
      market: { all: num(mAll), month: num(mMonth), monthly: mMonthly.map(numRow) },
      service: { all: num(sAll), month: num(sMonth), monthly: sMonthly.map(numRow) }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(
    `Server running on http://localhost:${PORT}`
  );
});