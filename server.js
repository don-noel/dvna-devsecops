'use strict';

/**
 * ============================================================================
 * FICHIER : server.js
 * OBJECTIF : Correction SAST - suppression des "var" + bonnes pratiques
 * ============================================================================
 *
 * ERREURS CORRIGÉES :
 * ------------------
 * 1) Utilisation de "var"
 *    - Problème : portée globale / hoisting / redéfinition possible
 *    - Impact : SonarQube → HIGH (bad practice)
 *
 *    Correction :
 *    → remplacement par const
 *
 * 2) Amélioration sécurité session (bonus)
 *    - ajout httpOnly
 */

const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');
const session = require('express-session');
const ejs = require('ejs');
const morgan = require('morgan');
const fileUpload = require('express-fileupload');
const config = require('./config/server');

// =========================
// INITIALISATION APP
// =========================

// ERREUR AVANT : var app
// CORRECTION : const (ne change jamais)
const app = express();

// Init passport config
require('./core/passport')(passport);

// =========================
// MIDDLEWARES
// =========================

app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(morgan('tiny'));

app.use(bodyParser.urlencoded({ extended: false }));

app.use(fileUpload());

// Reverse proxy (optionnel)
// app.set('trust proxy', 1);

// =========================
// SESSION
// =========================

app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: true // 🔥 amélioration sécurité (évite accès JS)
  }
}));

// =========================
// PASSPORT
// =========================

app.use(passport.initialize());
app.use(passport.session());

// Flash messages
app.use(require('express-flash')());

// =========================
// ROUTES
// =========================

app.use('/app', require('./routes/app')());
app.use('/', require('./routes/main')(passport));

// =========================
// SERVER
// =========================

app.listen(config.port, config.listen);
