const mongoose = require('mongoose');

const Schema = mongoose.Schema({
  username: {type: String, unique: true },
  password: {type: String}
});

module.exports = mongoose.model('user', Schema);