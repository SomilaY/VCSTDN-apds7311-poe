const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const ExpressBrute = require('express-brute');
const helmet = require('helmet');
const morgan = require('morgan');
const app = express();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const User = require('./models/User');
const Post = require('./models/Post');

app.use(morgan('combined'));
app.use(helmet());
app.use(cookieParser());
app.use(cors({ origin: 'http://localhost:4200', credentials: true }));

app.use(bodyParser.json());

// Load SSL certificates
const privateKey = fs.readFileSync('keys/privatekey.pem', 'utf8');
const certificate = fs.readFileSync('keys/certificate.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };

// MongoDB Connection
const mongoose = require('mongoose');
const mongoDBUri = 'mongodb+srv://SomilaY:Thekingishere16@somilacluster.kul1amk.mongodb.net/?ssl=true'; 

mongoose.connect(mongoDBUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('MongoDB connected');
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
  });

  const jwtSecretKey = 'Tottenham';

  function generateToken(user) {
    const payload = {
      id: user._id,
      email: user.email
    };
    const options = {
      expiresIn: '2h'
    };
    return jwt.sign(payload, jwtSecretKey, options);
  }
  
  
  function authenticateUser(req, res, next) {
    const token = req.cookies.token;
  
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: Token not provided' });
    }
  
    jwt.verify(token, jwtSecretKey, (err, decoded) => {
      if (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
      }
  
      req.user = decoded;
      next();
    });
}

const store = new ExpressBrute.MemoryStore();
const bruteforce = new ExpressBrute(store);
app.post('/auth',
    bruteforce.prevent, 
    function (req, res, next) {
        res.send('Success!');
    }
);

// GET all posts
app.get('/posts', authenticateUser, async (req, res) => {
  try {
    const posts = await Post.find(); // Retrieve all posts from the database
    res.json(posts);
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ error: 'An error occurred while fetching posts' });
  }
});;

// POST to create a new post
app.post('/posts', authenticateUser, async (req, res) => {
  const { title, content } = req.body;

  try {
    const newPost = new Post({ title, content });
    await newPost.save(); // Save the new post to the database
    res.status(201).json(newPost);
  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ error: 'An error occurred while creating the post' });
  }
});

// DELETE a post by ID
app.delete('/posts/:id', authenticateUser, async (req, res) => {
  const postId = req.params.id;

  try {
    const deletedPost = await Post.deleteOne({ _id: postId });
    if (deletedPost.deletedCount === 0) {
      res.status(404).json({ error: `Post with ID ${postId} not found` });
    } else {
      res.json({ message: `Post with ID ${postId} deleted successfully` });
    }
  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).json({ error: 'An error occurred while deleting the post' });
  }
});



// Define a POST route for user registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ error: 'Email is already registered' });
    }

    const newUser = new User({
      name,
      email,
      password: await bcrypt.hash(password, 10),
    });

    await newUser.save();

    res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'An error occurred while registering the user' });
  }
});

// Define a GET route for /register
app.get('/register', (req, res) => {
  res.send('This is the registration page.');
});


// POST to login an existing user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = generateToken(user);

    // Set the JWT token as a HTTP cookie
    res.cookie('token', token, { httpOnly: true });

    res.json({ message: 'Logged in successfully' });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ error: 'An error occurred while logging in the user' });
  }
});

module.exports = app;
