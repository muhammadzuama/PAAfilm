const express = require('express');
const App = express();
const bcrypt = require('bcrypt');
const { pool } = require('./config');
const flash = require("express-flash");
const session = require("express-session");
const bodyParser = require('body-parser');
const passport = require("passport")
const initializePassport = require("./passportConfig");
initializePassport(passport);
const LocalStrategy = require("passport-local").Strategy;


const PORT = process.env.PORT || 4000;

App.set("view engine", "ejs");
App.use(bodyParser.urlencoded({ extended: false }));

App.use(
  session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
  })
);
App.use(passport.initialize())
App.use(passport.session())

App.use(flash());

App.get('/', (req, res) => {
  res.render('index');
});

App.get('/users/register', (req, res) => {
  res.render('register');
});

App.post('/users/register', async (req, res) => {
  let { name, email, password, password2 } = req.body;

  let errors = [];

  console.log({
    name,
    email,
    password,
    password2
  });

  if (!name || !email || !password || !password2) {
    errors.push({ message: "Please enter all fields" });
  }

  if (password.length < 6) {
    errors.push({ message: "Password must be at least 6 characters long" });
  }

  if (password !== password2) {
    errors.push({ message: "Passwords do not match" });
  }

  if (errors.length > 0) {
    res.render("register", { errors, name, email, password, password2 });
  } else {
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      console.log(hashedPassword);
      pool.query(
        `SELECT * FROM users WHERE email = $1`,
        [email],
        (err, results) => {
          if (err) {
            console.log(err);
            throw err;
          }
          console.log(results.rows);

          if (results.rows.length > 0) {
            errors.push({
              message: "Email already registered"
            });
            res.render('register', { errors });
          } else {
            pool.query(
              `INSERT INTO users (name, email, password)
              VALUES ($1, $2, $3)
              RETURNING id, password`,
              [name, email, hashedPassword],
              (err, results) => {
                if (err) {
                  console.log(err);
                  throw err;
                }
                console.log(results.rows);
                req.flash("success_msg", "You are now registered. Please log in");
                res.redirect("/users/login");
              }
            );
          }
        }
      );
    } catch (err) {
      console.error(err);
      res.status(500).send("Server Error");
    }
  }
});

App.get('/users/login', (req, res) => {
  res.render('login');
});

App.get('/users/dashboard', (req, res) => {
  res.render('dashboard', { user: req.user.name });
});

App.get('/users/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error(err);
      return res.redirect('/users/dashboard');
    }
    req.flash('success_msg', 'Anda telah keluar dari sistem');
    res.redirect('/users/login');
  });
});
App.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
  })
);


App.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
