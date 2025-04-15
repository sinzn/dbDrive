const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const db = require('./db');
const app = express();
require('dotenv').config();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = `./uploads/${req.session.user.username}`;
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir);
    cb(null, userDir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});

const upload = multer({ storage });

// Authentication Middleware
function isAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') return next();
  res.redirect('/dashboard');
}

// Routes
app.get('/', (req, res) => res.redirect('/login'));

// Registration Route
app.get('/register', (req, res) => res.sendFile(__dirname + '/views/register.html'));

app.post('/register', (req, res) => {
  const { username, password, role } = req.body;

  // Check if the username already exists
  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.log("Error checking if user exists:", err);
      return res.send('Error occurred while registering');
    }

    if (results.length > 0) {
      return res.send('User already exists');
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.log("Error hashing password:", err);
        return res.send('Error occurred while registering');
      }

      // Insert new user with hashed password and role
      db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role || 'user'], (err, results) => {
        if (err) {
          console.log("Error inserting user:", err);
          return res.send('Error occurred while inserting user');
        }

        // Redirect to login page after successful registration
        res.redirect('/login');
      });
    });
  });
});

// Login Route
app.get('/login', (req, res) => res.sendFile(__dirname + '/views/login.html'));

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.log("Error fetching user:", err);
      return res.send('Error occurred while logging in');
    }

    if (results.length === 0) {
      return res.send('Invalid credentials');
    }

    const user = results[0];

    // Compare password with the hashed password
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.log("Error comparing password:", err);
        return res.send('Error occurred while logging in');
      }

      if (!isMatch) {
        return res.send('Invalid credentials');
      }

      // Save the user data in session
      req.session.user = user;

      // Redirect based on role
      res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
    });
  });
});

// Dashboard Route
app.get('/dashboard', isAuth, (req, res) => {
  const userDir = `./uploads/${req.session.user.username}`;
  fs.readdir(userDir, (err, files) => {
    if (err) {
      console.log("Error reading user files:", err);
      return res.send('Error loading your files');
    }
    res.render('dashboard', { username: req.session.user.username, files });
  });
});

// File Upload Route
app.post('/upload', isAuth, upload.single('file'), (req, res) => {
  res.redirect('/dashboard');
});

// File Download Route
app.get('/download/:filename', isAuth, (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.session.user.username, req.params.filename);
  res.download(filePath);
});

// Admin Route
app.get('/admin', isAdmin, (req, res) => {
  fs.readdir('./uploads', (err, users) => {
    const allData = {};
    users.forEach(user => {
      const files = fs.readdirSync(`./uploads/${user}`);
      allData[user] = files;
    });
    res.render('admin', { allData });
  });
});

// Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Server Setup
app.listen(3000, () => console.log('Server started on http://localhost:3000'));
