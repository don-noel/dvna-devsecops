'use strict';

/**
 * ============================================================================
 * FICHIER : core/passport.js
 * OBJECTIF : Correction SAST + amélioration maintenabilité
 * ============================================================================
 *
 * CORRECTIONS APPLIQUÉES :
 * -----------------------
 * 1) Suppression variable globale implicite
 *    → findOrCreateUser déclaré avec const
 *
 * 2) Suppression nesting > 4 niveaux (HIGH Sonar)
 *    → utilisation de async/await
 *    → early return
 *
 * 3) Amélioration lisibilité
 *    → code linéaire
 *    → suppression des .then() imbriqués
 *
 * 4) Bonnes pratiques
 *    → const au lieu de var
 *    → === au lieu de ==
 */

const db = require('../models');
const LocalStrategy = require('passport-local').Strategy;
const bCrypt = require('bcryptjs');

module.exports = function (passport) {

	// =========================
	// Helpers
	// =========================

	const isValidPassword = (user, password) => {
		return bCrypt.compareSync(password, user.password);
	};

	const createHash = (password) => {
		return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
	};

	// =========================
	// Serialize / Deserialize
	// =========================

	passport.serializeUser((user, done) => {
		done(null, user.id);
	});

	passport.deserializeUser(async (uid, done) => {
		try {
			const user = await db.User.findOne({
				where: { id: uid }
			});

			if (!user) {
				return done(null, false);
			}

			return done(null, user);

		} catch (error) {
			return done(error, false);
		}
	});

	// =========================
	// LOGIN
	// =========================

	passport.use('login', new LocalStrategy(
		{ passReqToCallback: true },
		async (req, username, password, done) => {
			try {
				const user = await db.User.findOne({
					where: { login: username }
				});

				if (!user) {
					return done(null, false, req.flash('danger', 'Invalid Credentials'));
				}

				if (!isValidPassword(user, password)) {
					return done(null, false, req.flash('danger', 'Invalid Credentials'));
				}

				return done(null, user);

			} catch (error) {
				return done(error);
			}
		}
	));

	// =========================
	// SIGNUP
	// =========================

	passport.use('signup', new LocalStrategy(
		{ passReqToCallback: true },
		async (req, username, password, done) => {

			/**
			 * AVANT (PROBLÈME) :
			 * - .then() imbriqués
			 * - if imbriqués
			 * - > 4 niveaux → Sonar HIGH
			 *
			 * MAINTENANT :
			 * - async/await
			 * - early return
			 * - code lisible
			 */

			try {
				const existingUser = await db.User.findOne({
					where: { email: username }
				});

				if (existingUser) {
					return done(null, false, req.flash('danger', 'Account Already Exists'));
				}

				// Validation des champs
				if (
					!req.body.email ||
					!req.body.password ||
					!req.body.username ||
					!req.body.cpassword ||
					!req.body.name
				) {
					return done(null, false, req.flash('danger', 'Input field(s) missing'));
				}

				// Vérification mot de passe
				if (req.body.password !== req.body.cpassword) {
					return done(null, false, req.flash('danger', 'Passwords dont match'));
				}

				// Création utilisateur
				const createdUser = await db.User.create({
					email: req.body.email,
					password: createHash(password),
					name: req.body.name,
					login: username
				});

				return done(null, createdUser);

			} catch (error) {
				return done(error);
			}
		}
	));
};
