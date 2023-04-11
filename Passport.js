const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const authD = require('./models/AuthD');
const passport = require("passport");


  passport.serializeUser((user, done) => {
    done(null, user);
  });
  
  passport.deserializeUser((user, done) => {
    done(null, user);
  });


passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:5000/api/auth/google/callback',
  passReqToCallback : true
},
function(request, accessToken, refreshToken, profile, cb) {
     //console.log(profile);
  authD.findOne({ social_id: profile.id}, function (err, user) {
    if (err) return cb(err, null);

        if (!user) {
          let newUser = new authD({
          name: profile.displayName,
          social_id: profile.id,
          username : profile.displayName,
          email : profile.emails[0]?.value,
          profilePic:profile.photos[0]?.value,
          verified:true,       
          });
          newUser.save();
          return cb(null, newUser);
        } else {
          return cb(null, user);
        }
  });
}
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: 'http://localhost:5000/api/auth/facebook/callback',
    passReqToCallback : true
  },
  function(request, accessToken, refreshToken, profile, cb) {
    authD.findOne({ social_id: profile.id}, function (err, user) {
      if (err) return cb(err, null);
          if (!user) {
            let newUser = new authD({
            name: profile.displayName,
            username : profile.username? profile.username:profile.id,
            social_id: profile.id,
            email : profile.id,
            verified:true,  
            });
            newUser.save();
            return cb(null, newUser);
          } else {
            return cb(null, user);
          }
    });
  }
));

passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_CONSUMER_KEY,
    consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
    callbackURL: 'http://localhost:5000/api/auth/twitter/callback',
    passReqToCallback : true
  },
  function(request, accessToken, refreshToken, profile, cb) {
    authD.findOne({ social_id: profile.id}, function (err, user) {
      
      if (err) return cb(err, null);

          if (!user) {
            let newUser = new authD({
            name: profile.displayName,
            username : profile.username,
            social_id: profile.id,
            email : profile.id,
            profilePic:profile.photos[0]?.value,
            verified:true,
            });
            newUser.save();
            return cb(null, newUser);
          } else {
            // if we find an user just return return user
            return cb(null, user);
          }
    });
  }
));


