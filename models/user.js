const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
  googleId: String,
  email: String,
  password: String,
  username: String
});

// Hashes the password before saving the user
UserSchema.methods.generateHash = async function (password) {
  return await bcrypt.hash(password, bcrypt.genSaltSync(8), null);
};

// Compares a provided password with the hashed password in the database
UserSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', UserSchema);

module.exports = User;
