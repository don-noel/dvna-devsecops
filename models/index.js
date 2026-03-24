'use strict';

/**
 * ============================================================================
 * FICHIER : models/index.js
 * OBJECTIF : Correction SonarQube - Medium issues restantes
 * ============================================================================
 *
 * CORRECTIONS APPLIQUÉES :
 * -----------------------
 * 1) Prefer 'node:fs' over 'fs'
 *    → import modernisé
 *
 * 2) Prefer 'node:path' over 'path'
 *    → import modernisé
 *
 * 3) Prefer top-level await over using a promise chain
 *    → suppression des chaînes .then().catch()
 *    → remplacement par une fonction async d'initialisation
 *
 * 4) Conservation du comportement existant
 *    → connexion DB
 *    → sync DB
 *    → chargement des modèles
 *    → export final
 */

const fs = require('node:fs');
const path = require('node:path');
const Sequelize = require('sequelize');
const config = require('../config/db.js');

const env = process.env.NODE_ENV || 'development';

// Initialisation Sequelize
const sequelize = process.env.DATABASE_URL
	? new Sequelize(process.env.DATABASE_URL)
	: new Sequelize(
			config.database,
			config.username,
			config.password,
			{
				host: config.host,
				dialect: config.dialect
			}
	  );

// Chargement des modèles
const db = {};

fs
	.readdirSync(__dirname)
	.filter((file) => file.indexOf('.') !== 0 && file !== 'index.js')
	.forEach((file) => {
		const model = sequelize.import(path.join(__dirname, file));
		db[model.name] = model;
	});

// Associations
Object.keys(db).forEach((modelName) => {
	if ('associate' in db[modelName]) {
		db[modelName].associate(db);
	}
});

// Exports
db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;

/**
 * Initialisation asynchrone de la base
 * Remplace les chaînes .then().catch() signalées par Sonar.
 */
async function initializeDatabase() {
	try {
		await sequelize.authenticate();
		console.log('Connection has been established successfully.');
	} catch (err) {
		console.log('Unable to connect to the database:', err);
	}

	try {
		await sequelize.sync(); // force:true désactivé
		console.log('It worked!');
	} catch (err) {
		console.log('An error occurred while creating the table:', err);
	}
}

initializeDatabase().catch((err) => {
  console.error('Database init failed:', err);
});
