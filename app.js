require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Connect to MongoDB ---
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// --- User Schema ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isMember: { type: Boolean, default: false },
  avatar: { type: String, default: 'https://i.pravatar.cc/150' },
  posts: [
    {
      content: String,
      createdAt: { type: Date, default: Date.now }
    }
  ]
});

const User = mongoose.model('User', userSchema);

// --- Middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// --- Sessions ---
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
}));

// --- Auth Middleware ---
function checkAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// --- Routes ---

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Register
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.send('Username already exists');

    const hashedPassword = await bcrypt.hash(password, 12);
    const avatarUrl = `https://i.pravatar.cc/150?img=${Math.floor(Math.random() * 70) + 1}`;

    const user = new User({ username, password: hashedPassword, avatar: avatarUrl });
    await user.save();

    req.session.userId = user._id;
    req.session.user = user;

    res.redirect('/members');
  } catch (err) {
    console.error(err);
    res.send('Error registering user');
  }
});

// Login
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.send('Invalid username or password');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.send('Invalid username or password');

    req.session.userId = user._id;
    req.session.user = user;

    res.redirect('/members');
  } catch (err) {
    console.error(err);
    res.send('Error logging in');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error(err);
    res.redirect('/');
  });
});

// Members page
app.get('/members', checkAuth, async (req, res) => {
  const user = await User.findById(req.session.userId);
  res.render('members', { user });
});

// Add a post
app.post('/members/post', checkAuth, async (req, res) => {
  const { content } = req.body;
  try {
    const user = await User.findById(req.session.userId);
    user.posts.unshift({ content });
    await user.save();
    res.redirect('/members');
  } catch (err) {
    console.error(err);
    res.send('Error posting message');
  }
});

// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
