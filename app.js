require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

// Initialization passport configuration
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// Intialize session and passport
app.use(session({
	secret: "Our little secret",
	resave: false,
	saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

const url = "mongodb://127.0.0.1:27017/userDB";

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect(url);
}

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
	googleId: String,
	facebookId: String,
	secret: String
});


// userSchema.plugin(encrypt, 
// 	{
// 		secret: process.env.SECRET,
// 		encryptedFields: ["password"]
// }); 

userSchema.plugin(passportLocalMongoose); // passport
userSchema.plugin(findOrCreate); // findOrCreate

const User = mongoose.model("User", userSchema);

//passport authentication
passport.use(User.createStrategy());
passport.serializeUser((user, done) => {
	done(null, user.id);
});
passport.deserializeUser((id, done) => {
	User.findById(id)
	.then(user => {
		done(null, user);
	})
	.catch(err => {
		done(err, null);
	});
});

// Google OAuth goes here
passport.use(new GoogleStrategy({
	clientID: process.env.CLIENT_ID,
	clientSecret: process.env.CLIENT_SECRET,
	callbackURL: "http://localhost:3000/auth/google/secrets",
	userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
	},
	function(accessToken, refreshToken, profile, cb) {
		console.log(profile);
		User.findOrCreate({ googleId: profile.id }, (err, user) =>{
			return cb(err, user);
		});
	}
));

// Facebook OAuth goes here
passport.use(new FacebookStrategy({
	clientID: process.env.FACEBOOK_APP_ID,
	clientSecret: process.env.FACEBOOK_APP_SECRET,
	callbackURL: "http://localhost:3000/auth/facebook/secrets"
	},
	function(accessToken, refreshToken, profile, cb) {
		User.findOrCreate({ facebookId: profile.id }, (err, user) => {
			return cb(err, user);
		});
	}
));

app.route('/')
	.get((req, res) => {
		res.render('home');
	})

// Google authenticate requests
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

// Facebook authenticate requests
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.route('/register')
	.get((req, res) => {
		res.render('register');
	})
	// .post((req, res) => {
	// 	bcrypt.hash("qwerty", saltRounds, 
	// 		(err, hash) => {
	// 			// Store hash in your password DB.
	// 			const newUser = new User({
	// 				email: req.body.username,
	// 				// password: md5(req.body.password)
	// 				password: hash
	// 			});
	// 			newUser.save()
	// 				.then(() => {
	// 					console.log('Successfully registered');
	// 					res.render('secrets');
	// 				})
	// 				.catch(err => {
	// 					console.log(err);
	// 				})
	// 	});
		
	// })
	.post((req, res) => {
		// passport authentication
		User.register({username: req.body.username}, req.body.password)
			.then(() => {
				passport.authenticate("local")(req, res, () => {
					res.redirect('/secrets');
				})
			})
			.catch(err => {
				console.log(err);
				res.redirect('/register');
			});
	})

app.route('/login')
	.get((req, res) => {
		res.render('login');
	})
	// .post((req, res) => {
	// 	const username = req.body.username;
	// 	// const password = md5(req.body.password);
	// 	const password = req.body.password;
		
	// 	User.findOne({email: username})
	// 	.then(foundUser => {
	// 		if (foundUser) {
	// 			bcrypt.compare(password, foundUser.password)
	// 				.then((result) => {
	// 					// result == true
	// 					if (result === true) {
	// 						res.render('secrets');
	// 					}
	// 				})
	// 				.catch(error => {
	// 					console.log(error);
	// 				});	
	// 		}
	// 	})
	// 	.catch(err => {
	// 		console.log(err);
	// 	});
	// })
	.post((req, res) => {
		//passport authentication
		const user = new User({
			username: req.body.username,
			password: req.body.password
		});

		req.login(user, (err) => {
			if (err) {
				console.log(err);
			} else {
				passport.authenticate("local")(req, res, () => {
					res.redirect('/secrets');
				});
			}
		})
	})

app.route('/secrets')
	.get((req, res) => {
		User.find({"secret": {$ne: null}})
			.then((foundUser) => {
				res.render("secrets", {usersWithSecrets: foundUser});
			})
			.catch(err => console.log(err));
	});

app.route('/logout')
	.get((req, res) => {
		req.logout((err) => {
			if (err) {
				console.log(err);
			} else {
				res.redirect('/');
			}
		});
	})

app.route('/submit')
	.get((req, res) => {
		if (req.isAuthenticated()) {
			res.render('submit');
		} else {
			res.redirect('/login');
		}
	})
	.post((req, res) => {
		const submmitedSecret = req.body.secret;
		User.findById(req.user.id)
			.then((foundUser) => {
				foundUser.secret = submmitedSecret;
				foundUser.save().then(() => res.redirect('/secrets'));
			});
	})

app.listen(3000, () => {
	console.log('listening on port 3000');
})