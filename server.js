const express = require('express');
const cookieParser = require("cookie-parser");
const bodyParser = require('body-parser');
const sessions = require('express-session');
const http = require('http');
const socketIO = require('socket.io');
const path = require('path');
const { MongoClient } = require('mongodb');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const config = require('./config');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

const oneDay = 1000 * 60 * 60 * 24;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

app.use(cookieParser());
app.use(bodyParser.json());

app.use(sessions({
  secret: "thisismysecrctekey",
  saveUninitialized: true,
  cookie: { maxAge: oneDay },
  resave: false
}));

// MongoDB connection URL
const mongoURL = 'mongodb://localhost:27017';
const dbName = 'ChatIMK';

function checkUserSession(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
}

mongoose.connect(config.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('MongoDB connected');
    // Start your server or do other initialization here
  })
  .catch((err) => console.error('MongoDB connection error:', err));


app.get('/', checkUserSession, function routeHandler(req, res) {
  res.sendFile('main.html', { root: 'public' });
});
// app.get('/', checkUserSession, function routeHandler(req, res){
//     checkUserSession();
//   });

app.get('/test', function routeHandler(req, res) {
  res.send('ok');
});

app.get('/login', (req, res) => {
  res.sendFile('login.html', { root: 'public' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const client = await MongoClient.connect(mongoURL, { useNewUrlParser: true, useUnifiedTopology: true });
    const db = client.db(dbName);
    const usersCollection = db.collection('users');

    // Check if the user exists in the database
    const user = await usersCollection.findOne({ username });

    if (user && await bcrypt.compare(password, user.password)) {
      // If the user exists and the password matches

      // Assuming 'user._id' is the user's ID in MongoDB
      req.session.user = { id: user._id, username: user.username };

      client.close();
      return res.json({ message: 'Login successful' });
    }

    // If the credentials are incorrect or the user does not exist
    client.close();
    res.status(401).json({ message: 'Invalid username or password' });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//for debugging add new user purposes
app.get('/register', async (req, res) => {
  // Replace the destructuring assignment with hardcoded values
  const staticUsername = 'yanwei';
  const staticPassword = '2';

  try {
    const client = await MongoClient.connect(mongoURL, { useNewUrlParser: true, useUnifiedTopology: true });
    const db = client.db(dbName);
    const usersCollection = db.collection('users');

    // Check if the username is already taken
    const existingUser = await usersCollection.findOne({ username: staticUsername });
    if (existingUser) {
      client.close();
      return res.status(400).json({ message: 'Username already taken' });
    }

    // Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(staticPassword, 10);

    // Insert the new user into the database
    const newUser = { username: staticUsername, password: hashedPassword };
    const result = await usersCollection.insertOne(newUser);

    client.close();
    res.json({ message: 'User registered successfully', userId: result.insertedId });
  } catch (error) {
    console.error('Error during user registration:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/get',function(req, res){
  // res.send(req.session.user);
  const usernameget = req.session.user.username;
    res.send({ usernameget });
  });

// Sample route to demonstrate logging out and destroying the session
app.get('/logout', (req, res) => {
  // Check if req.session.user exists
  if (req.session.user) {
    // Access the username from req.session.user
    const username = req.session.user.username;

    // Destroy the session
    req.session.destroy((err) => {
      if (err) {
        res.status(500).json({ message: 'Error during logout' });
      } else {
        res.json({ message: `Logout successful for ${username}` });
      }
    });
  } else {
    res.status(401).json({ message: 'User not found in session' });
  }
});

app.get('/chat', (req, res) => {
  res.sendFile('chat.html', { root: 'public' });
});

const users = {};

// Function to get chat history from MongoDB
function getChatHistory() {
  return Message.find().sort({ time: 1 }).exec();
}

io.on('connection', (socket) => {
  // Emit chat history to the connecting client
  getChatHistory().then((chatHistory) => {
    socket.emit('chatHistory', chatHistory);
  });
  
  socket.on('setUsername', (username) => {
    socket.username = username;
    users[socket.id] = { username, startTime: new Date() };
    io.emit('userConnected', { username, time: new Date() });
    
    // Log the username to the console
    console.log(`User ${socket.id} set username to: ${username}`);
    console.log('Users after setting username:', users);
  });

  socket.on('sendMessage', (message) => {
    const user = users[socket.id];
  
    if (user && user.username) {
      const username = user.username;
      const time = new Date();
      if (message === '!users') {
        // If the message is '!users', send the active users and their login times
        const activeUsers = Object.values(users)
          .map((userData) => `${userData.username} (logged in at ${userData.startTime})`)
          .join(', ');
  
        // Emit a serverMessage event to the requesting user
        socket.emit('serverMessage', { content: `Active users: ${activeUsers}`, time });
      } else if (message === '!time') {
        socket.emit('serverMessage', { content: `Waktu saat ini: ${time}`, time });
      } else {
        const userMessage = { user: socket.id, username, content: message, time };
        io.emit('userMessage', userMessage);
        saveMessageToMongoDB(userMessage);
        
        // Log the message to the command prompt
        console.log(`${formatTime(time)} - ${username}: ${message}`);
      }
    } else {
      // Handle the case when the user is not defined or doesn't have a username
      console.error('User is not defined or does not have a username');
    }
  });

  // Helper function to format time
  function formatTime(time) {
    const options = { hour: 'numeric', minute: 'numeric', second: 'numeric' };
    return new Intl.DateTimeFormat('en-US', options).format(time);
  }
  
  // // Save a new message
  // const newMessage = new Message({
  //   user: 'someUserId',
  //   username: 'JohnDoe',
  //   content: 'Hello, World!',
  // });
  
  // newMessage.save()
  // .then(() => console.log('Message saved to MongoDB'))
  // .catch((err) => console.error('Error saving message:', err));
  
  // // Retrieve messages
  // Message.find()
  // .then((messages) => console.log('Retrieved messages:', messages))
  // .catch((err) => console.error('Error retrieving messages:', err));

  // Function to save the message to MongoDB
  function saveMessageToMongoDB(message) {
    const user = users[socket.id];
    console.log("ini dari saveMessage");
    console.log(message);
    if (user && user.username) {
      const username = user.username;
      const time = new Date(); // Assuming this is a Date object

      const userMessage = new Message({
        user: socket.id,
        username,
        content: message.content, // Access 'content' instead of the entire 'message' object
        time: time.toISOString(), // Convert Date to string
      });

      userMessage.save()
        .then(() => {
          // Log the message to the console
          console.log(`${formatTime(time)} - ${username}: ${message.content}`);
        })
        .catch((err) => console.error('Error saving message to MongoDB:', err));
    }
  }

  socket.on('disconnect', () => {
    const username = users[socket.id] ? users[socket.id].username : 'Unknown';
  
    // Broadcast to all clients that a user has left
    io.emit('userDisconnected', { username, time: new Date() });

    delete users[socket.id]

    // Log the user disconnection to the console
    console.log(`User disconnected: ${socket.id}, ${username}`);
    console.log('Users after user disconnect:', users);
  });
  
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
