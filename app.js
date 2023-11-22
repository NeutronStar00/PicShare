const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { google } = require('googleapis');
const multer = require('multer');
const fs = require('fs');
const stream = require('stream');
const session = require('express-session');
const User = require('./models/user');
const app = express();
const dotenv = require('dotenv'); // Import dotenv
dotenv.config(); // Load environment variables from .env file

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI);

// Set up passport
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
  scope: ['profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  console.log('Google Profile:', profile);
  try {
    const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
    const username = profile.displayName || null;
    const user = await User.findOne({ googleId: profile.id });

    if (!user) {
      const newUser = new User({ googleId: profile.id, email, username });
      await newUser.save();
      done(null, newUser);
    } else {
      done(null, user);
    }
  } catch (err) {
    done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Middleware
app.use(session({
  secret: '9270add33bce8a53a7532007cea843947a489a3564c4848f85beae8dbe3964ef',
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
  res.render('home', { user: req.user });
});

app.get('/profile', (req, res) => {
  // Check if a file was uploaded by looking at the session
  const fileUploaded = req.session.uploadedFile ? true : false;

  res.render('profile', { user: req.user, fileUploaded, uploadedFile: req.session.uploadedFile });
});

// Auth routes
app.get('/auth/google', (req, res, next) => {
  // Determine the state based on the referer (previous page)
  const isSignup = req.headers.referer && req.headers.referer.includes('/signup');
  
  passport.authenticate('google', {
    state: isSignup ? 'signup' : 'login',
  })(req, res, next);
});

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    console.log(req.user)
    // Custom callback function to handle redirection
    const redirectCallback = () => {
      // Check if the user is authenticated after the authentication attempt
      if (req.isAuthenticated()) {
        // User is authenticated, redirect to the profile page
        res.redirect('/profile');
      } else {
        // User is not authenticated, redirect based on the state
        const redirectTo = req.query.state === 'signup' ? '/signup' : '/';
        res.redirect(redirectTo);
      }
    };

    // Call the custom callback function after a short delay
    // This allows Passport to set isAuthenticated correctly
    setTimeout(redirectCallback, 100);
  }
);


app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if email and password are provided
  if (!email || !password) {
    return res.status(400).send('Email and password are required.');
  }

  try {
    // Check if the user exists
    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      console.log('User not found.');
      return res.redirect('/signup'); // Redirect to signup page
    }

    // Check if the entered password matches the stored hash
    const passwordMatch = await existingUser.comparePassword(password);

    if (!passwordMatch) {
      console.log('Invalid password.');
      return res.redirect('/'); // Redirect to home page
    }

    // Log in the user
    req.login(existingUser, (err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      return res.redirect('/profile');
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/signup', async (req, res) => {
  const { email, password, username } = req.body;

  // Check if email, password, and username are provided
  if (!email || !password || !username) {
    return res.status(400).send('Email, password, and username are required.');
  }

  try {
    // Check if the user already exists
    const user = await User.findOne({ email });

    if (user) {
      console.log('User already exists. Redirecting to login page:', email);
      return res.redirect('/'); // Redirect to homepage for login
    }

    // Create a new user account
    const newUser = new User({ email, password, username });

    // Hash the password before saving
    newUser.password = await newUser.generateHash(password);

    await newUser.save();

    // Log in the user
    req.login(newUser, (err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      res.redirect('/profile'); // Redirect to the user's profile page
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Set up OAuth2 client using environment variables
const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_CALLBACK_URL
);

// Check if we have previously stored a token
fs.readFile('token.json', (err, token) => {
  if (err) {
    getAccessToken(oAuth2Client);
  } else {
    oAuth2Client.setCredentials(JSON.parse(token));
  }
});

// Function to get an access token and store it to 'token.json'
function getAccessToken(oAuth2Client) {
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/drive.file'],
  });
  console.log('Authorize this app by visiting this URL:', authUrl);
}

// Middleware for handling file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post('/upload', upload.single('file'), (req, res) => {
  const file = req.file;

  if (!file) {
    return res.status(400).send('No file uploaded.');
  }

  const drive = google.drive({ version: 'v3', auth: oAuth2Client });

  const driveFileMetadata = {
    name: file.originalname,
    mimeType: file.mimetype,
  };

  const driveFileMedia = {
    mimeType: file.mimetype,
    body: createReadStreamFromBuffer(file.buffer),
  };

  drive.files.create(
    {
      resource: driveFileMetadata,
      media: driveFileMedia,
    },
    (err, driveFile) => {
      if (err) {
        console.error('Error uploading file to Google Drive:', err);
        return res.status(500).send('Error uploading file to Google Drive.');
      }

      res.send(`File uploaded to Google Drive: ${driveFile.data.name}`);
    }
  );
});

// Function to create a readable stream from a buffer
function createReadStreamFromBuffer(buffer) {
  const readable = new stream.Readable();
  readable._read = () => {};
  readable.push(buffer);
  readable.push(null);
  return readable;
}

// Server starting
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
