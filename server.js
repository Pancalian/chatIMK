const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const path = require('path');
const mongoose = require('mongoose');
const config = require('./config');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

mongoose.connect(config.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('MongoDB connected');
    // Start your server or do other initialization here
  })
  .catch((err) => console.error('MongoDB connection error:', err));

const users = {};

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

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
