const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const connection = require("./database");
const User = connection.models.User;
const RefreshTokenTable = connection.models.RefreshTokenTable;
const validPassword = require("../lib/passwordUtils.js").validPassword;
const createUser = require("../lib/createUser").createUser;

passport.use(new LocalStrategy(
    (username, password, done) => {
      User.findOne({ username: username })
          .then((user) => {
              if (!user) { 
                return done(null, false) 
              }
              const isValid = validPassword(password, user.hash, user.salt);
              
              if (isValid) {
                  return done(null, user);
              } else {
                  return done(null, false);
              }
          })
          .catch((err) => {   
              console.log(`login failed: ${err}`);
              done(err);
          });
    })
);

/**
 * Goole OAuth
 */
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    }, async (accessToken, refreshToken, profile, done) => { 
    // find the user in the database
    User.findOne({ googleId: profile.id })
    .then((user) => {
        if (user) {
            // generate refresh token
            RefreshTokenTable.findOne({userId: user._id})
            .then((userId_uuid) => {
                if(!userId_uuid){
                    console.log("No user found");
                    return done(null, false);
                }
                return done(null, {user, userId_uuid});
            })
            .catch((err) => {
                console.log(`Error: ${err}`);
                return done(err);
            });
        } else{
            const newUser = new User({
                username: null,
                googleId: profile.id,
                hash: null,
                salt: null,
            });
            createUser(newUser)
            .then((message) => {
                    console.log("User created");
                    RefreshTokenTable.findOne({userId: newUser._id})
                    .then((userId_uuid) => {
                        if(!userId_uuid){
                            console.log("No user found");
                            return done(null, false);
                        }
                        return done(null, {newUser, userId_uuid});
                    })
                })
            .catch((err) => {
                    console.log(`Error: ${err}`);
                    return done(err);
                });
        }
    })
    .catch((err) => {
        console.log(`Error: ${err}`);
        return done(err);
    });
}));



// passport.serializeUser((user, done) => {
//   done(null, user.id);
// });

// passport.deserializeUser((userId, done) => {
//   User.findById(userId)
//     .then((user) => {
//       done(null, user);
//     })
//     .catch((err) => done(err));
// });
