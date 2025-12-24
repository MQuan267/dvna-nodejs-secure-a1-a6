/*var db = require('../models')
var bCrypt = require('bcrypt')
var md5 = require('md5')

module.exports.isAuthenticated = function (req, res, next) {
	if (req.isAuthenticated()) {
		req.flash('authenticated', true)
		return next();
	}
	res.redirect('/login');
}

module.exports.isNotAuthenticated = function (req, res, next) {
	if (!req.isAuthenticated())
		return next();
	res.redirect('/learn');
}

module.exports.forgotPw = function (req, res) {
	if (req.body.login) {
		db.User.find({
			where: {
				'login': req.body.login
			}
		}).then(user => {
			if (user) {
				// Send reset link via email happens here
				req.flash('info', 'Check email for reset link')
				res.redirect('/login')
			} else {
				req.flash('danger', "Invalid login username")
				res.redirect('/forgotpw')
			}
		})
	} else {
		req.flash('danger', "Invalid login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPw = function (req, res) {
	if (req.query.login) {
		db.User.find({
			where: {
				'login': req.query.login
			}
		}).then(user => {
			if (user) {
				if (req.query.token == md5(req.query.login)) {
					res.render('resetpw', {
						login: req.query.login,
						token: req.query.token
					})
				} else {
					req.flash('danger', "Invalid reset token")
					res.redirect('/forgotpw')
				}
			} else {
				req.flash('danger', "Invalid login username")
				res.redirect('/forgotpw')
			}
		})
	} else {
		req.flash('danger', "Non Existant login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPwSubmit = function (req, res) {
	if (req.body.password && req.body.cpassword && req.body.login && req.body.token) {
		if (req.body.password == req.body.cpassword) {
			db.User.find({
				where: {
					'login': req.body.login
				}
			}).then(user => {
				if (user) {
					if (req.body.token == md5(req.body.login)) {
						user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
						user.save().then(function () {
							req.flash('success', "Passowrd successfully reset")
							res.redirect('/login')
						})
					} else {
						req.flash('danger', "Invalid reset token")
						res.redirect('/forgotpw')
					}
				} else {
					req.flash('danger', "Invalid login username")
					res.redirect('/forgotpw')
				}
			})
		} else {
			req.flash('danger', "Passowords do not match")
			res.render('resetpw', {
				login: req.query.login,
				token: req.query.token
			})
		}

	} else {
		req.flash('danger', "Invalid request")
		res.redirect('/forgotpw')
	}
}*/
var db = require('../models')
var bCrypt = require('bcrypt')
const crypto = require('crypto')
const { Op } = db.Sequelize
const { sendResetMail } = require('./mailer')

module.exports.isAuthenticated = function (req, res, next) {
  if (req.isAuthenticated()) {
    req.flash('authenticated', true)
    return next()
  }
  res.redirect('/login')
}

module.exports.isNotAuthenticated = function (req, res, next) {
  if (!req.isAuthenticated()) return next()
  res.redirect('/learn')
}

module.exports.forgotPw = function (req, res) {
  if (!req.body.login) {
    req.flash('danger', 'Invalid login username')
    return res.redirect('/forgotpw')
  }

  db.User.findOne({ where: { login: req.body.login } })
    .then(user => {
      if (!user) {
        req.flash('danger', 'Invalid login username')
        return res.redirect('/forgotpw')
      }

      const rawToken = crypto.randomBytes(32).toString('hex')
      const hashedToken = crypto
        .createHash('sha256')
        .update(rawToken)
        .digest('hex')

      return db.PassReset.create({
        login: user.login,
        token: hashedToken,
        expires: new Date(Date.now() + 15 * 60 * 1000)
      }).then(() => {
  		const resetLink = `https://secure.vinhlongxaxu.id.vn/resetpw?token=${rawToken}`

		return sendResetMail(user.email, resetLink)
			.then(() => {
			req.flash('info', 'Check your email for reset link')
			res.redirect('/login')
			})
			.catch(() => {
			req.flash('danger', 'Failed to send reset email')
			res.redirect('/forgotpw')
			})
		})

    })
    .catch(() => {
      req.flash('danger', 'Something went wrong')
      res.redirect('/forgotpw')
    })
}

module.exports.resetPw = function (req, res) {
  if (!req.query.token) {
    req.flash('danger', 'Invalid reset token')
    return res.redirect('/forgotpw')
  }

  const hashedToken = crypto
    .createHash('sha256')
    .update(req.query.token)
    .digest('hex')

  db.PassReset.findOne({
    where: {
      token: hashedToken,
      expires: { [Op.gt]: new Date() }
    }
  }).then(record => {
    if (!record) {
      req.flash('danger', 'Invalid or expired reset token')
      return res.redirect('/forgotpw')
    }

    res.render('resetpw', { token: req.query.token })
  })
}

module.exports.resetPwSubmit = function (req, res) {
  if (!req.body.token || !req.body.password || !req.body.cpassword) {
    req.flash('danger', 'Invalid request')
    return res.redirect('/forgotpw')
  }

  if (req.body.password !== req.body.cpassword) {
    req.flash('danger', 'Passwords do not match')
    return res.redirect('/forgotpw')
  }

  const hashedToken = crypto
    .createHash('sha256')
    .update(req.body.token)
    .digest('hex')

  db.PassReset.findOne({
    where: {
      token: hashedToken,
      expires: { [Op.gt]: new Date() }
    }
  }).then(record => {
    if (!record) {
      req.flash('danger', 'Invalid or expired reset token')
      return res.redirect('/forgotpw')
    }

    db.User.findOne({ where: { login: record.login } })
      .then(user => {
        if (!user) {
          req.flash('danger', 'Invalid user')
          return res.redirect('/forgotpw')
        }

        user.password = bCrypt.hashSync(req.body.password, 10)

        user.save()
          .then(() => {
            return db.PassReset.destroy({
              where: { token: hashedToken }
            })
          })
          .then(() => {
            req.flash('success', 'Password successfully reset')
            res.redirect('/login')
          })
      })
  })
}

module.exports.requireRole = function (role) 
{
    return function (req, res, next) 
   {
        if (!req.isAuthenticated()) {
            return res.status(401).send('Unauthenticated');
        }
        if (!req.user || req.user.role !== role) {
            return res.status(403).send('Forbidden');
        }
        next();
    }
}
