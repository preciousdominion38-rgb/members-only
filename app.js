require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const app = express();
const PORT = process.env.PORT || 3000;

const MONGO_URI = process.env.MONGO_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!MONGO_URI) {
  console.error('ERROR: MONGO_URI environment variable not set.');
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.error('ERROR: SESSION_SECRET environment variable not set.');
  process.exit(1);
}

// Connect to MongoDB
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Define User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isMember: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());   // in case you ever need JSON
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Session configuration
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGO_URI }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 }  // 1 day
}));

// Authentication check
function checkAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.redirect('/login');
}

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    if (!username || !password) {
      return res.send('Username and password are required.');
    }
    const existing = await User.findOne({ username });
    if (existing) {
      return res.send('Username already taken.');
    }
    const hashed = await bcrypt.hash(password, 12);
    const user = new User({ username, password: hashed });
    await user.save();

    // Set session
    req.session.userId = user._id;
    req.session.user = { username: user.username, isMember: user.isMember };

    return res.redirect('/members');
  } catch (err) {
    console.error('Register error:', err);
    return res.send('Error registering user.');
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    if (!username || !password) {
      return res.send('Username and password are required.');
    }
    const user = await User.findOne({ username });
    if (!user) {
      return res.send('Invalid username or password.');
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send('Invalid username or password.');
    }

    // Set session
    req.session.userId = user._id;
    req.session.user = { username: user.username, isMember: user.isMember };

    return res.redirect('/members');
  } catch (err) {
    console.error('Login error:', err);
    return res.send('Error logging in.');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('Session destroy error:', err);
    res.redirect('/');
  });
});

app.get('/members', checkAuth, (req, res) => {
  res.render('members', { user: req.session.user });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
