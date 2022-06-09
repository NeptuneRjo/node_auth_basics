const express = require('express')
const path = require('path')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const mongoose = require('mongoose')
const Schema = mongoose.Schema
const bcrypt = require('bcryptjs')

require('dotenv').config()

// Database
const mongoURI = process.env.MONGO_URI
mongoose.connect(mongoURI, { useUnifiedTopology: true, useNewUrlParser: true })

const db = mongoose.connection
db.on('error', console.error.bind(console, 'mongo connection error'))

const User = mongoose.model(
	'User',
	new Schema({
		username: { type: String, required: true },
		password: { type: String, required: true },
	})
)

// App
const app = express()
app.set('views', __dirname)
app.set('view engine', 'ejs')

// Passport
app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

passport.serializeUser(function (user, done) {
	done(null, user.id)
})

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user)
	})
})

passport.use(
	new LocalStrategy((username, password, done) => {
		User.findOne({ username: username }, (err, user) => {
			if (err) {
				return done(err)
			}
			if (!user) {
				return done(null, false, { message: 'Incorrect username' })
			}
			// if (user.password !== password) {
			// 	return done(null, false, { message: 'Incorrect password' })
			// }

			if (user.password !== password) {
				bcrypt.compare(password, user.password, (err, res) => {
					if (res) {
						// passwords match! log user in
						return done(null, user)
					} else {
						console.log('an error has occured', err)
						// passwords do not match!
						return done(null, false, { message: 'Incorrect password' })
					}
				})
			}

			// return done(null, user)
		})
	})
)

app.use((req, res, next) => {
	res.locals.currentUser = req.user
	next()
})

// Routes
app.get('/', (req, res) => res.render('index', { user: req.params }))

app.get('/sign-up', (req, res) => res.render('sign-up-form'))
app.post('/sign-up', (req, res, next) => {
	// const user = new User({
	// 	username: req.body.username,
	// 	password: req.body.password,
	// }).save((err) => {
	// 	if (err) {
	// 		return next(err)
	// 	}
	// 	res.redirect('/')
	// })
	bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
		if (err) {
			return next(err)
		}
		const user = new User({
			username: req.body.username,
			password: hashedPassword,
		}).save((err) => {
			if (err) {
				return next(err)
			}
			res.redirect('/')
		})
	})
})

app.post(
	'/log-in',
	passport.authenticate('local', {
		successRedirect: '/',
		failureRedirect: '/',
	})
)

app.get('/log-out', (req, res) => {
	req.logout((err) => {
		if (err) {
			return next(err)
		}
		res.redirect('/')
	})
})

const port = process.env.PORT || 3000

app.listen(port, () => console.log('app listening on port 3000'))
