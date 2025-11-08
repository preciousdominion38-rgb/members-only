require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const app = express();
const PORT = process.env.PORT || 3000;

// Check environment variables
if (!process.env.MONGO_URI || !process.env.SESSION_SECRET) {
  console.error("ERROR: MONGO_URI or SESSION_SECRET not set!");
  process.exit(1);
}

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch(err => {
  console.error("MongoDB connection error:", err);
  process.exit(1);
});

// User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isMember: { type: Boolean, default: false },
  posts: [
    {
      content: { type: String, required: true },
      createdAt: { type: Date, default: Date.now }
    }
  ]
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Sessions
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Authentication middleware
function checkAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// Routes

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Register
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send('Username and password required.');

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.send('Username already exists.');

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    req.session.userId = newUser._id;
    req.session.user = { username: newUser.username, isMember: newUser.isMember };
    res.redirect('/members');
  } catch (err) {
    console.error("Registration error:", err);
    res.send("Error registering user.");
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send('Username and password required.');

  try {
    const user = await User.findOne({ username });
    if (!user) return res.send('Invalid username or password.');

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send('Invalid username or password.');

    req.session.userId = user._id;
    req.session.user = { username: user.username, isMember: user.isMember };
    res.redirect('/members');
  } catch (err) {
    console.error("Login error:", err);
    res.send("Error logging in.");
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
  try {
    const user = await User.findById(req.session.userId).lean();
    if (!user.posts) user.posts = [];
    res.render('members', { user });
  } catch (err) {
    console.error(err);
    res.send("Error loading members page");
  }
});

// Post submission
app.post('/members/post', checkAuth, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === "") return res.redirect('/members');

  try {
    await User.findByIdAndUpdate(
      req.session.userId,
      { $push: { posts: { content } } }
    );
    res.redirect('/members');
  } catch (err) {
    console.error(err);
    res.send("Error posting message");
  }
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
