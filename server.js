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
  const { name, description, emoji } = req.body;

  db.query(
    'INSERT INTO categories (name, description, emoji) VALUES (?, ?, ?)',
    [name, description, emoji],
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
        emoji
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
    cover_img
  } = req.body;

  db.query(
    `UPDATE categories 
     SET name=?, description=?, emoji=?, cover_img=? 
     WHERE id=?`,
    [
      name,
      description,
      emoji,
      cover_img || null,
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

          const result = products.map(product => ({
            ...product,
            images: imageMap[product.id] || []
          }));

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
    images
  } = req.body;

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
      description
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      category_id,
      title,
      price,
      sub_category,
      condition_type,
      location,
      phone,
      description
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
    images
  } = req.body;

  db.query(
    `UPDATE products
    SET
      title=?,
      price=?,
      sub_category=?,
      condition_type=?,
      location=?,
      phone=?,
      description=?
    WHERE id=?`,
    [
      title,
      price,
      sub_category,
      condition_type,
      location,
      phone,
      description,
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

// Start server
app.listen(PORT, () => {
  console.log(
    `Server running on http://localhost:${PORT}`
  );
});