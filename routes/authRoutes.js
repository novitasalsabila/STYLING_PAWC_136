const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../database/db');
const router = express.Router();

const session = require('express-session');
const app = express();

// Middleware untuk parsing body request
app.use(express.urlencoded({ extended: true }));

// Setup session middleware
app.use(session({
    secret: 'your-secret-key',  // Gantilah dengan kunci yang lebih aman
    resave: false,
    saveUninitialized: true,
}));

// Middleware untuk menambahkan `user` ke res.locals
app.use((req, res, next) => {
    res.locals.user = req.session.userId; // Mengambil userId dari session
    next();
});

// Route Signup
router.post('/signup', (req, res) => {
    const { username, password } = req.body;

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).send('Error hashing password');

        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err, result) => {
            if (err) return res.status(500).send('Error registering user');
            res.redirect('/login');
        });
    });
});

// Route untuk menampilkan form signup
router.get('/signup', (req, res) => {
    res.render('signup', {
        layout: 'layouts/main-layout'
    });
});

// Route Login
router.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).send('Error fetching user');
        if (results.length === 0) return res.status(400).send('User not found');

        bcrypt.compare(password, results[0].password, (err, isMatch) => {
            if (err) return res.status(500).send('Error checking password');
            if (!isMatch) return res.status(401).send('Incorrect password');

            // Simpan userId dalam sesi setelah login berhasil
            req.session.userId = results[0].id;
            res.redirect('/'); // Arahkan ke halaman utama setelah login
        });
    });
});

// Route untuk menampilkan form login
router.get('/login', (req, res) => {
    res.render('login', {
        layout: 'layouts/main-layout'
    });
});

// Route Logout
router.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).send('Error logging out');
        res.redirect('/login'); // Arahkan ke halaman login setelah logout
    });
});

module.exports = router;