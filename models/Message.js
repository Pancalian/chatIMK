// models/Message.js
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  user: String,
  username: String,
  content: String,
  time: { type: Date, default: Date.now },
});

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;
