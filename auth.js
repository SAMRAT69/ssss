const express = require('express');
const passport = require('passport');
const config = require('../config.json');
const LocalStrategy = require('passport-local').Strategy;
const { v4: uuidv4 } = require('uuid');
const { db } = require('../handlers/db.js');
const { sendWelcomeEmail, sendPasswordResetEmail, sendVerificationEmail } = require('../handlers/email.js');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const router = express.Router();

// Initialize passport
router.use(passport.initialize());
router.use(passport.session());

passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const settings = await db.get('settings') || {};
      const users = await db.get('users');
      if (!users) {
        return done(null, false, { message: 'No users found.' });
      }

      const isEmail = username.includes('@');
      let user;
      if (isEmail) {
        user = users.find(user => user.email === username);
      } else {
        user = users.find(user => user.username === username);
      }

      if (!user) {
        return done(null, false, { message: 'Incorrect username or email.' });
      }

      if (!user.verified && (settings.emailVerification || false)) {
        return done(null, false, { message: 'Email not verified. Please verify your email.', userNotVerified: true });
      }

      const match = await bcrypt.compare(password, user.password);
      if (match) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    } catch (error) {
      return done(error);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.username);
});

passport.deserializeUser(async (username, done) => {
  try {
    const users = await db.get('users');
    if (!users) {
      throw new Error('User not found');
    }

    const foundUser = users.find(user => user.username === username);
    if (!foundUser) {
      throw new Error('User not found');
    }

    done(null, foundUser);
  } catch (error) {
    done(error);
  }
});

async function doesUserExist(username) {
  const users = await db.get('users');
  return users ? users.some(user => user.username === username) : false;
}

async function doesEmailExist(email) {
  const users = await db.get('users');
  return users ? users.some(user => user.email === email) : false;
}

async function createUser(username, email, password) {
  const settings = await db.get('settings') || {};
  const emailVerificationEnabled = settings.emailVerification || false;

  const default_resources = {
    ram: config.total_resources.ram,
    disk: config.total_resources.disk,
    cores: config.total_resources.cores
  };

  const max_resources = await db.get('resources-' + email);
  if (!max_resources) {
    console.log('Starting Resources Creation for ' + email);
    await db.set('resources-' + email, default_resources);
    console.log('Resources created for ' + email, await db.get('resources-' + email));
  }

  return addUserToUsersTable(username, email, password, !emailVerificationEnabled);
}

async function addUserToUsersTable(username, email, password, verified) {
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userId = uuidv4();
    const verificationToken = verified ? null : generateRandomCode(30);
    let users = await db.get('users') || [];
    const newUser = { userId, username, email, password: hashedPassword, accessTo: [], admin: false, welcomeEmailSent: false, verified, verificationToken };
    users.push(newUser);
    await db.set('users', users);

    if (!newUser.welcomeEmailSent) {
      await sendWelcomeEmail(email, username, password);
      newUser.welcomeEmailSent = true;

      if (!verified) {
        await sendVerificationEmail(email, verificationToken);
        users = await db.get('users') || [];
        const index = users.findIndex(u => u.userId === newUser.userId);
        if (index !== -1) {
          users[index] = newUser;
          await db.set('users', users);
        }
      }
    }

    return users;
  } catch (error) {
    console.error('Error adding user to database:', error);
    throw error;
  }
}

router.get('/auth/login', async (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      if (info.userNotVerified) {
        return res.redirect('/login?err=UserNotVerified');
      }
      return res.redirect('/login?err=InvalidCredentials');
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      res.redirect('/');
    });
  })(req, res, next);
});

module.exports = router;
