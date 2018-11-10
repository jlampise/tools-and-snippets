const express = require('express');
const bodyParser = require('body-parser');
//const apiRouter = require('./apirouter');
//const mongoose = require('mongoose');
const userModel = require('./models/user');
const bcrypt = require('bcrypt-nodejs');
const session = require('express-session');
const mongoStore = require('connect-mongo')(session);
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;

const app = express();

app.use(bodyParser.json());


// THIS WILL SET req.session
app.use(
  session({
    name: 'myapp-id',
    resave: false,
    secret: 'myBestSecret',
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
    store: new mongoStore({
      collection: 'session',
      url: 'mongodb://localhost:27017/mydb',
      ttl: 24 * 60 * 60
    })
  })
);


app.use(passport.initialize());

// THIS WILL SET req.user
app.use(passport.session());

passport.use(
  'local-login',
  new localStrategy(
    {
      usernameField: 'username',
      passwordField: 'password',
      passReqToCallback: true
    },
    function(req, username, password, done) {
      if (!req.body.username || !req.body.password) {
        return done(null, false, 'Wrong username or password');
      }
      userModel.findOne({ username }, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, 'Wrong username or password');
        }
        if (isPasswordValid(password, user.password)) {
          let token = createToken();
          req.session.token = token;
          req.session.username = username;
          return done(null, user);
        }
        return done(null, false, 'Wrong username or password');
      });
    }
  )
);

passport.serializeUser(function(user, done) {
  return done(null, user._id);
});


//THIS WILL RETURN OBJECT TO BE PUT AS req.user
passport.deserializeUser(function(_id, done) {
  userModel.findById(_id, '-password', function(err, user) {
    if (err || !user) {
      return done(err);
    }
    return done(null, user);
  });
});



// mongoose.connect('mongodb://localhost:27017/mydb').then(
//   () => {
//     console.log('MongoDB connection success');
//   },
//   error => {
//     console.error('MongoDB connection failure! Error: ' + error);
//     process.exit(-1);
//   }
// );

function isUserLogged(req, res, next) {
  const token = req.headers.token;
  if (req.isAuthenticated()) {
    if (token === req.session.token) {
      return next();
    }
    return res.status(403).json({ message: 'not allowed' });
  }
}

function createToken() {
  let token = '';
  let letters = 'abcdefghijklmnABCDEFGHIJKLMN1234567890';
  for (let i = 0; i < 1024; i++) {
    let j = Math.floor(Math.random() * 38);
    token = token + letters[j];
  }
  return token;
}

function createHash(pw) {
  return bcrypt.hashSync(pw, bcrypt.genSaltSync(8), null);
}

function isPasswordValid(pw, hash) {
  return bcrypt.compareSync(pw, hash);
}

// LOGIN API

app.post('/register', function(req, res) {
  if (
    !req.body.username ||
    !req.body.password ||
    req.body.username.length === 0 ||
    req.body.password === 0
  ) {
    return res.status(409).json({ message: 'username already in use' });
  }

  const user = new userModel({
    username: req.body.username,
    password: createHash(req.body.password)
  });
  user.save((err) => {
    if (err) {
      return res.status(409).json({ message: 'username already in use' });
    } else {
      return res.status(200).json({ message: 'success' });
    }
  });
});

app.post(
  '/login',
  passport.authenticate('local-login', { failureRedirect: '/' }),
  function(req, res) {
    return res
      .status(200)
      .json({ message: 'success', token: req.session.token });
  }
);

app.post('/logout', function(req, res) {
  if (req.session) {
    req.logout();
    req.session.destroy(); //Removes from db
    return res.status(200).json({ message: 'success' });
  }
  return res.status(404).json({ message: 'not found' });
});

// GET USERS

app.get('/users', isUserLogged, function(req, res) {
  userModel.find({}, 'username', (err, users) => {
    if (err) {
      return res.status(404).json({ message: 'not found' });
    } else {
      let usernames = [];
      users.forEach(user => {
        usernames.push(user.username);
      });
      res.status(200).json(usernames);
    }
  });
});

//app.use('/api', isUserLogged, apiRouter);

app.listen(3001);
