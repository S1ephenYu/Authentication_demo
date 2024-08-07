const router = require('express').Router();
const passport = require('passport');
const genPassword = require('../lib/passwordUtils').genPassword;
const connection = require('../config/database');
const User = connection.models.User;
const RefreshTokenTable = connection.models.RefreshTokenTable;
const createUser = require('../lib/createUser').createUser;
const mongoose = require('mongoose');
const isAuth = require('./authMiddleware').isAuth;
const isAdmin = require('./authMiddleware').isAdmin;
const {generateRefreshJWT} = require('../lib/generateJWT');

/**
 * -------------- POST ROUTES ----------------
 */

router.post('/login', (req, res, next) => {
    passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err || !user) {
            return res.status(400).json({ message: info ? info.message : 'Login failed' });
        }
        
        // find the refresh token for the use
        const userId_uuid = RefreshTokenTable.findOne({userId: user._id})
        .then((userId_uuid) => {
            if(!userId_uuid){
                console.log("No user found");
                return res.redirect('/login-failure');
            }
            res.cookie('refreshToken', generateRefreshJWT(userId_uuid), { httpOnly: true, secure: true });
            return res.redirect('/login-success');
        })
        .catch((err) => {
            console.log(`Error: ${err}`);
            return res.redirect('/login-failure');
        });
      })(req, res, next);
});
  

 router.post('/register', async (req, res, next) => {
    // hash and salt password
    const {salt, hash} = genPassword(req.body.pw);

    // check if username already exists
    const username = req.body.username;
    const user = await User.findOne({ username: username });
    if (user) {
        console.log("user already exists");
        return res.redirect('/register');
    }

    // create new user
    const newUser = new User({
        username: username,
        hash: hash,
        salt: salt,
        googleId: null,
    });
    createUser(newUser)
    .then((message) => {
        return res.redirect('/login');
    })
    .catch((err) => {
        console.log(err);
        return res.redirect('/register');
    });
 });


 /**
 * -------------- GET ROUTES ----------------
 */

router.get('/', (req, res, next) => {
    res.send('<h1>Home</h1><p>Please <a href="/register">register</a></p> <a href="/auth/google">google</a>');
});

// When you visit http://localhost:3000/login, you will see "Login Page"
router.get('/login', (req, res, next) => {
   
    const form = '<h1>Login Page</h1><form method="POST" action="/login">\
    Enter Username:<br><input type="text" name="username">\
    <br>Enter Password:<br><input type="password" name="password">\
    <br><br><input type="submit" value="Submit"></form>';

    res.send(form);

});

// When you visit http://localhost:3000/register, you will see "Register Page"
router.get('/register', (req, res, next) => {
    const form = '<h1>Register Page</h1><form method="post" action="register">\
                    Enter Username:<br><input type="text" name="username">\
                    <br>Enter Password:<br><input type="password" name="pw">\
                    <br><br><input type="submit" value="Submit"></form>';

    res.send(form);
    
});

// Google OAuth
router.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));
  
router.get('/auth/google/callback', 
    passport.authenticate('google', { session: false ,failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.cookie('refreshToken', generateRefreshJWT(req.user.userId_uuid), { httpOnly: true, secure: true });
        console.log("Successful authentication");
        res.redirect('/');
});


/**
 * Lookup how to authenticate users on routes with Local Strategy
 * Google Search: "How to use Express Passport Local Strategy"
 * 
 * Also, look up what behaviour express session has without a maxage set
 */
router.get('/protected-route', isAuth, (req, res, next) => {
    res.send('You made it to the route.');
});

router.get('/admin-route', isAdmin, (req, res, next) => {
    res.send('You made it to the admin route.');
});

// Visiting this route logs the user out
router.get('/logout', (req, res, next) => {
    // req.logout();
    res.clearCookie('refreshToken');
    res.clearCookie('accessToken');
    res.redirect('/protected-route');
});

router.get('/login-success', (req, res, next) => {
    res.send('<p>You successfully logged in. --> <a href="/protected-route">Go to protected route</a></p>');
});

router.get('/login-failure', (req, res, next) => {
    res.send('You entered the wrong password.');
});



module.exports = router;