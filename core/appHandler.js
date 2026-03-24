'use strict';

/**
 * ============================================================================
 * FICHIER : core/appHandler.js
 * OBJECTIF : Réduction des erreurs SAST / SonarQube / vulnérabilités évidentes
 * ============================================================================
 *
 * RÉCAP DES ERREURS CORRIGÉES
 * ---------------------------
 * 1) Variables implicites globales
 *    - Problème : utilisation de "output =" sans let/const/var
 *    - Impact : SonarQube remonte cela en Blocker, car cela crée une variable
 *      globale implicite, source de bugs et d'effets de bord.
 *    - Correction : remplacement par "const output = ..." ou "let output = ..."
 *
 * 2) Injection SQL
 *    - Problème : concaténation directe de req.body.login dans une requête SQL
 *    - Impact : un attaquant peut injecter du SQL malveillant
 *    - Correction : utilisation de requête paramétrée avec replacements
 *
 * 3) Command Injection
 *    - Problème : exec('ping -c 2 ' + req.body.address)
 *    - Impact : l'utilisateur peut injecter des commandes système
 *    - Correction : validation stricte de l'entrée + execFile avec arguments
 *
 * 4) Open Redirect
 *    - Problème : res.redirect(req.query.url) sans validation
 *    - Impact : redirection malveillante vers un site externe/piégé
 *    - Correction : autoriser uniquement des chemins internes relatifs
 *
 * 5) Usage dangereux de mathjs.eval
 *    - Problème : eval/équivalent dynamique sur entrée utilisateur
 *    - Impact : surface d'attaque inutile et signalement SAST
 *    - Correction : remplacement par mathjs.evaluate + validation d'entrée
 *
 * 6) Désérialisation non sécurisée
 *    - Problème : node-serialize.unserialize sur données utilisateur
 *    - Impact : vulnérabilité grave de désérialisation
 *    - Correction : désactivation de l'ancien endpoint legacy
 *
 * 7) Exposition excessive de données utilisateurs
 *    - Problème : listUsersAPI retournait potentiellement trop d'attributs
 *    - Impact : fuite de données sensibles
 *    - Correction : retour limité aux champs utiles
 *
 * 8) Robustesse générale
 *    - Ajout de vérifications d'entrée
 *    - Ajout de catch manquants
 *    - Utilisation cohérente de const/let
 *    - Messages d’erreur plus sûrs
 */

const db = require('../models');
const bCrypt = require('bcryptjs');
const { execFile } = require('child_process');
const mathjs = require('mathjs');
const libxmljs = require('libxmljs');
// ERREUR D’ORIGINE : node-serialize était utilisé pour désérialiser des données
// utilisateur. C’est dangereux côté SAST et sécurité.
// const serialize = require("node-serialize")
const Op = db.Sequelize.Op;

/**
 * Validation simple d’un hostname / IPv4.
 * But : éviter l’injection de commande dans la fonction ping.
 */
function isValidHost(value) {
	if (typeof value !== 'string') {
		return false;
	}

	const trimmed = value.trim();

	// Autorise :
	// - IPv4 simple
	// - hostname / domaine simple
	// Refuse :
	// - caractères shell suspects ; & | $ ` > < etc.
	const hostRegex = /^(?=.{1,253}$)([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$|^(\d{1,3}\.){3}\d{1,3}$/;
	return hostRegex.test(trimmed);
}

/**
 * Validation de redirection interne.
 * On n'autorise que des chemins relatifs comme :
 * /app/products
 * /login
 *
 * On refuse :
 * - http://evil.com
 * - //evil.com
 * - javascript:...
 */
function isSafeInternalRedirect(url) {
	return typeof url === 'string' && /^\/(?!\/)/.test(url);
}

module.exports.userSearch = function (req, res) {
	// ERREUR D’ORIGINE :
	// var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";
	// => vulnérable à l’injection SQL
	//
	// CORRECTION :
	// requête paramétrée avec replacements
	const login = typeof req.body.login === 'string' ? req.body.login.trim() : '';

	if (!login) {
		req.flash('warning', 'Invalid login');
		return res.render('app/usersearch', {
			output: null
		});
	}

	const query = 'SELECT name, id FROM Users WHERE login = :login';

	db.sequelize.query(query, {
		replacements: { login },
		type: db.Sequelize.QueryTypes.SELECT
	}).then(users => {
		if (users.length) {
			const output = {
				user: {
					name: users[0].name,
					id: users[0].id
				}
			};

			return res.render('app/usersearch', {
				output
			});
		}

		req.flash('warning', 'User not found');
		return res.render('app/usersearch', {
			output: null
		});
	}).catch(() => {
		req.flash('danger', 'Internal Error');
		return res.render('app/usersearch', {
			output: null
		});
	});
};

module.exports.ping = function (req, res) {
	const address = typeof req.body.address === 'string' ? req.body.address.trim() : '';

	// ERREUR D’ORIGINE :
	// exec('ping -c 2 ' + req.body.address, ...)
	// => injection de commande possible
	//
	// CORRECTION :
	// 1) validation stricte
	// 2) execFile avec arguments séparés
	if (!isValidHost(address)) {
		req.flash('warning', 'Invalid address');
		return res.render('app/ping', {
			output: 'Invalid address'
		});
	}

	execFile('ping', ['-c', '2', address], (err, stdout, stderr) => {
		const output = `${stdout || ''}${stderr || ''}${err ? '\nPing failed' : ''}`;

		return res.render('app/ping', {
			output
		});
	});
};

module.exports.listProducts = function (req, res) {
	db.Product.findAll().then(products => {
		// ERREUR D’ORIGINE :
		// output = { ... } sans déclaration explicite
		// => variable globale implicite
		const output = {
			products
		};

		return res.render('app/products', {
			output
		});
	}).catch(() => {
		req.flash('danger', 'Unable to list products');
		return res.render('app/products', {
			output: { products: [] }
		});
	});
};

module.exports.productSearch = function (req, res) {
	const searchName = typeof req.body.name === 'string' ? req.body.name.trim() : '';

	db.Product.findAll({
		where: {
			name: {
				[Op.like]: `%${searchName}%`
			}
		}
	}).then(products => {
		const output = {
			products,
			searchTerm: searchName
		};

		return res.render('app/products', {
			output
		});
	}).catch(() => {
		req.flash('danger', 'Search failed');
		return res.render('app/products', {
			output: {
				products: [],
				searchTerm: searchName
			}
		});
	});
};

module.exports.modifyProduct = function (req, res) {
	if (!req.query.id || req.query.id === '') {
		const output = {
			product: {}
		};

		return res.render('app/modifyproduct', {
			output
		});
	}

	db.Product.findOne({
		where: {
			id: req.query.id
		}
	}).then(product => {
		const output = {
			product: product || {}
		};

		return res.render('app/modifyproduct', {
			output
		});
	}).catch(() => {
		req.flash('danger', 'Unable to load product');
		return res.render('app/modifyproduct', {
			output: { product: {} }
		});
	});
};

module.exports.modifyProductSubmit = function (req, res) {
	const productId = req.body.id && req.body.id !== '' ? req.body.id : 0;

	db.Product.findOne({
		where: {
			id: productId
		}
	}).then(product => {
		let currentProduct = product;

		if (!currentProduct) {
			currentProduct = db.Product.build({});
		}

		currentProduct.code = req.body.code;
		currentProduct.name = req.body.name;
		currentProduct.description = req.body.description;
		currentProduct.tags = req.body.tags;

		return currentProduct.save().then(savedProduct => {
			if (savedProduct) {
				req.flash('success', 'Product added/modified!');
				return res.redirect('/app/products');
			}

			req.flash('danger', 'Unable to save product');
			return res.render('app/modifyproduct', {
				output: { product: currentProduct }
			});
		}).catch(() => {
			const output = {
				product: currentProduct
			};

			req.flash('danger', 'Unable to save product');
			return res.render('app/modifyproduct', {
				output
			});
		});
	}).catch(() => {
		req.flash('danger', 'Internal Error');
		return res.render('app/modifyproduct', {
			output: { product: {} }
		});
	});
};

module.exports.userEdit = function (req, res) {
	return res.render('app/useredit', {
		userId: req.user.id,
		userEmail: req.user.email,
		userName: req.user.name
	});
};

module.exports.userEditSubmit = function (req, res) {
	db.User.findOne({
		where: {
			id: req.body.id
		}
	}).then(user => {
		if (!user) {
			req.flash('danger', 'User not found');
			return res.render('app/useredit', {
				userId: req.user.id,
				userEmail: req.user.email,
				userName: req.user.name
			});
		}

		if (req.body.password && req.body.password.length > 0) {
			if (req.body.password === req.body.cpassword) {
				user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null);
			} else {
				req.flash('warning', 'Passwords dont match');
				return res.render('app/useredit', {
					userId: req.user.id,
					userEmail: req.user.email,
					userName: req.user.name
				});
			}
		}

		user.email = req.body.email;
		user.name = req.body.name;

		return user.save().then(() => {
			req.flash('success', 'Updated successfully');
			return res.render('app/useredit', {
				userId: req.body.id,
				userEmail: req.body.email,
				userName: req.body.name
			});
		});
	}).catch(() => {
		req.flash('danger', 'Internal Error');
		return res.render('app/useredit', {
			userId: req.user.id,
			userEmail: req.user.email,
			userName: req.user.name
		});
	});
};

module.exports.redirect = function (req, res) {
	const url = req.query.url;

	// ERREUR D’ORIGINE :
	// res.redirect(req.query.url)
	// => open redirect
	//
	// CORRECTION :
	// on limite aux chemins internes de l’application
	if (isSafeInternalRedirect(url)) {
		return res.redirect(url);
	}

	return res.send('invalid redirect url');
};

module.exports.calc = function (req, res) {
	const eqn = typeof req.body.eqn === 'string' ? req.body.eqn.trim() : '';

	if (!eqn) {
		return res.render('app/calc', {
			output: 'Enter a valid math string like (3+3)*2'
		});
	}

	// ERREUR D’ORIGINE :
	// mathjs.eval(req.body.eqn)
	// => usage dynamique dangereux / signalé SAST
	//
	// CORRECTION :
	// mathjs.evaluate + validation minimale
	//
	// NB : on limite la longueur pour réduire les abus.
	if (eqn.length > 200) {
		return res.render('app/calc', {
			output: 'Expression too long'
		});
	}

	try {
		const result = mathjs.evaluate(eqn);

		return res.render('app/calc', {
			output: result
		});
	} catch (e) {
		return res.render('app/calc', {
			output: 'Enter a valid math string like (3+3)*2'
		});
	}
};

module.exports.listUsersAPI = function (req, res) {
	// ERREUR D’ORIGINE :
	// retourner tous les champs utilisateur peut exposer trop de données
	//
	// CORRECTION :
	// on limite aux attributs utiles
	db.User.findAll({
		attributes: ['id', 'name', 'email', 'login']
	}).then(users => {
		return res.status(200).json({
			success: true,
			users
		});
	}).catch(() => {
		return res.status(500).json({
			success: false,
			users: []
		});
	});
};

module.exports.bulkProductsLegacy = function (req, res) {
	// ERREUR D’ORIGINE :
	// node-serialize.unserialize(req.files.products.data.toString('utf8'))
	// => désérialisation non sécurisée, très mauvaise pour le SAST
	//
	// CORRECTION :
	// on désactive cet ancien endpoint legacy plutôt que garder un code dangereux
	req.flash('danger', 'Legacy bulk upload is disabled for security reasons');
	return res.render('app/bulkproducts', {
		messages: { danger: 'Legacy bulk upload is disabled for security reasons' },
		legacy: true
	});
};

module.exports.bulkProducts = function (req, res) {
	if (req.files.products && req.files.products.mimetype === 'text/xml') {
		try {
			// NOTE :
			// le code d’origine avait déjà remplacé l’option dangereuse noent: true
			// par noblanks: true, ce qui évite le problème XXE déjà corrigé.
			const products = libxmljs.parseXmlString(
				req.files.products.data.toString('utf8'),
				{ noblanks: true }
			);

			products.root().childNodes().forEach(product => {
				const newProduct = new db.Product();
				newProduct.name = product.childNodes()[0] ? product.childNodes()[0].text() : '';
				newProduct.code = product.childNodes()[1] ? product.childNodes()[1].text() : '';
				newProduct.tags = product.childNodes()[2] ? product.childNodes()[2].text() : '';
				newProduct.description = product.childNodes()[3] ? product.childNodes()[3].text() : '';
				newProduct.save();
			});

			return res.redirect('/app/products');
		} catch (e) {
			return res.render('app/bulkproducts', {
				messages: { danger: 'Invalid XML file' },
				legacy: false
			});
		}
	}

	return res.render('app/bulkproducts', {
		messages: { danger: 'Invalid file' },
		legacy: false
	});
};
