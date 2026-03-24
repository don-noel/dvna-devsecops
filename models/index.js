'use strict';

/**
 * ============================================================================
 * FICHIER : models/index.js
 * OBJECTIF : Correction SAST - suppression des "var" + bonnes pratiques
 * ============================================================================
 *
 * ERREURS CORRIGÉES :
 * ------------------
 * 1) Utilisation de "var"
 *    - Problème : portée imprécise, hoisting, re-déclaration possible
 *    - Impact : SonarQube remonte cela comme HIGH (bad practice)
 *
 *    Correction :
 *    → remplacement par const (valeurs immuables)
 *    → let si nécessaire (aucun cas ici)
 *
 *    Résultat :
 *    → suppression de plusieurs HIGH d’un coup
 *
 * 2) Lisibilité et cohérence
 *    - utilisation uniforme de const
 *    - code plus moderne (ES6)
 */

const fs = require("fs");
const path = require("path");
const Sequelize = require("sequelize");

// ERREUR AVANT : var env
// CORRECTION : const (ne change jamais)
const env = process.env.NODE_ENV || "development";

// ERREUR AVANT : var config
const config = require("../config/db.js");

// =========================
// INITIALISATION SEQUELIZE
// =========================

// ERREUR AVANT : var sequelize
// CORRECTION : let car valeur conditionnelle
let sequelize;

if (process.env.DATABASE_URL) {
  sequelize = new Sequelize(process.env.DATABASE_URL);
} else {
  sequelize = new Sequelize(
    config.database,
    config.username,
    config.password,
    {
      host: config.host,
      dialect: config.dialect
    }
  );
}

// =========================
// TEST CONNEXION DB
// =========================

sequelize
  .authenticate()
  .then(() => {
    console.log('Connection has been established successfully.');
  })
  .catch((err) => {
    console.log('Unable to connect to the database:', err);
  });

// =========================
// SYNC DB
// =========================

sequelize
  .sync() // ⚠️ force:true désactivé pour éviter destruction tables
  .then(() => {
    console.log('It worked!');
  })
  .catch((err) => {
    console.log('An error occurred while creating the table:', err);
  });

// =========================
// LOAD MODELS
// =========================

// ERREUR AVANT : var db
const db = {};

fs
  .readdirSync(__dirname)
  .filter((file) => {
    return file.indexOf(".") !== 0 && file !== "index.js";
  })
  .forEach((file) => {

    // ERREUR AVANT : var model
    const model = sequelize.import(path.join(__dirname, file));

    db[model.name] = model;
  });

// =========================
// ASSOCIATIONS
// =========================

Object.keys(db).forEach((modelName) => {
  if ("associate" in db[modelName]) {
    db[modelName].associate(db);
  }
});

// =========================
// EXPORT
// =========================

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;
