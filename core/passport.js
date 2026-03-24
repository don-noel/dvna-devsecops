'use strict';

/**
 * ============================================================================
 * FICHIER : core/passport.js
 * OBJECTIF : Réduction des erreurs SAST / SonarQube / bonnes pratiques
 * ============================================================================
 *
 * RÉCAP DES ERREURS CORRIGÉES
 * ---------------------------
 * 1) Variable globale implicite
 *    - Problème : "findOrCreateUser = function () { ... }"
 *    - Impact : sans let/const/var, JavaScript crée une variable globale implicite
 *      => SonarQube le signale en Blocker
 *    - Correction : remplacement par "const findOrCreateUser = function () { ... }"
 *
 * 2) Comparaison faible
 *    - Problème : usage de "==" au lieu de "==="
 *    - Impact : conversions implicites non souhaitées, moins sûr / moins propre
 *    - Correction : remplacement par "==="
 *
 * 3) Robustesse générale
 *    - Utilisation cohérente de const
 *    - Ajout de catch pour éviter les promesses silencieuses
 *    - Meilleure lisibilité
 *    - Messages d’erreur plus propres
 */

const db = require('../models');
const LocalStrategy = require('passport-local').Strategy;
const bCrypt = require('bcryptjs');

module.exports = function (passport) {
	/**
	 * Vérifie le mot de passe saisi contre le hash stocké.
	 */
	const isValidPassword = function (user, password) {
		return bCrypt.compareSync(password, user.password);
	};

	/**
	 * Génère le hash du mot de passe.
	 */
	const createHash = function (password) {
		return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
	};

	passport.serializeUser(function (user, done) {
		done(null, user.id);
	});

	passport.deserializeUser(function (uid, done) {
		db.User.findOne({
			where: {
				id: uid
			}
		}).then(function (user) {
			if (user) {
				return done(null, user);
			}

			return done(null, false);
		}).catch(function (error) {
			// Bonne pratique :
			// éviter qu'une erreur DB ne reste silencieuse
			return done(error, false);
		});
	});

	passport.use('login', new LocalStrategy(
		{
			passReqToCallback: true
		},
		function (req, username, password, done) {
			db.User.findOne({
				where: {
					login: username
				}
			}).then(function (user) {
				if (!user) {
					return done(null, false, req.flash('danger', 'Invalid Credentials'));
				}

				if (!isValidPassword(user, password)) {
					return done(null, false, req.flash('danger', 'Invalid Credentials'));
				}

				return done(null, user);
			}).catch(function (error) {
				return done(error);
			});
		}
	));

	passport.use('signup', new LocalStrategy(
		{
			passReqToCallback: true
		},
		function (req, username, password, done) {
			/**
			 * ERREUR D’ORIGINE :
			 * findOrCreateUser = function () { ... }
			 *
			 * POURQUOI C’EST UNE ERREUR :
			 * - absence de let / const / var
			 * - crée une variable globale implicite
			 * - SonarQube remonte cela comme Blocker
			 *
			 * CORRECTION :
			 * const findOrCreateUser = function () { ... }
			 *
			 * CE QUE ÇA RÉSOUT :
			 * - supprime le Blocker
			 * - évite les effets de bord globaux
			 * - rend la portée de la fonction explicite
			 */
			const findOrCreateUser = function () {
				db.User.findOne({
					where: {
						email: username
					}
				}).then(function (user) {
					if (user) {
						return done(null, false, req.flash('danger', 'Account Already Exists'));
					}

					if (
						req.body.email &&
						req.body.password &&
						req.body.username &&
						req.body.cpassword &&
						req.body.name
					) {
						/**
						 * ERREUR D’ORIGINE :
						 * if (req.body.cpassword == req.body.password)
						 *
						 * POURQUOI C’EST MOINS BIEN :
						 * - "==" autorise des conversions implicites
						 * - moins strict, moins propre
						 *
						 * CORRECTION :
						 * utiliser "==="
						 */
						if (req.body.cpassword === req.body.password) {
							return db.User.create({
								email: req.body.email,
								password: createHash(password),
								name: req.body.name,
								login: username
							}).then(function (createdUser) {
								return done(null, createdUser);
							}).catch(function (error) {
								return done(error);
							});
						}

						return done(null, false, req.flash('danger', 'Passwords dont match'));
					}

					return done(null, false, req.flash('danger', 'Input field(s) missing'));
				}).catch(function (error) {
					return done(error);
				});
			};

			process.nextTick(findOrCreateUser);
		}
	));
};
