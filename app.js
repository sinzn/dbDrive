const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const conn = require('./db');

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads'),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({ storage });

function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.is_admin) return next();
  res.redirect('/dashboard');
}

app.get('/', (req, res) => res.redirect('/login'));

app.get('/register', (req, res) => res.render('register'));
app.post('/register', (req, res) => {
  const { username, password, is_admin } = req.body;
  const adminFlag = is_admin ? 1 : 0;
  conn.query('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
    [username, password, adminFlag], () => res.redirect('/login'));
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  conn.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, results) => {
    if (results.length > 0) {
      req.session.user = results[0];
      res.redirect(results[0].is_admin ? '/admin' : '/dashboard');
    } else {
      res.send('Invalid credentials');
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/dashboard', isAuthenticated, (req, res) => {
  conn.query('SELECT * FROM files WHERE user_id = ?', [req.session.user.id], (err, files) => {
    res.render('dashboard', { user: req.session.user, files });
  });
});

app.post('/upload', isAuthenticated, upload.single('file'), (req, res) => {
  const uploadDate = new Date();
  conn.query(
    'INSERT INTO files (filename, originalname, user_id, uploaded_at) VALUES (?, ?, ?, ?)',
    [req.file.filename, req.file.originalname, req.session.user.id, uploadDate],
    () => res.redirect('/dashboard')
  );
});

app.post('/delete/:id', isAuthenticated, (req, res) => {
  const fileId = req.params.id;
  conn.query('SELECT * FROM files WHERE id = ? AND user_id = ?', [fileId, req.session.user.id], (err, results) => {
    if (results.length > 0) {
      fs.unlinkSync(path.join(__dirname, 'public/uploads', results[0].filename));
      conn.query('DELETE FROM files WHERE id = ?', [fileId], () => res.redirect('/dashboard'));
    } else {
      res.send('Not authorized');
    }
  });
});

app.get('/download/:filename', isAuthenticated, (req, res) => {
  const filePath = path.join(__dirname, 'public/uploads', req.params.filename);
  res.download(filePath);
});

app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
  conn.query('SELECT files.*, users.username FROM files JOIN users ON files.user_id = users.id', (err, files) => {
    res.render('admin_dashboard', { user: req.session.user, files });
  });
});

app.post('/admin/delete/:id', isAuthenticated, isAdmin, (req, res) => {
  const fileId = req.params.id;
  conn.query('SELECT * FROM files WHERE id = ?', [fileId], (err, results) => {
    if (results.length > 0) {
      fs.unlinkSync(path.join(__dirname, 'public/uploads', results[0].filename));
      conn.query('DELETE FROM files WHERE id = ?', [fileId], () => res.redirect('/admin'));
    } else {
      res.send('File not found');
    }
  });
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
