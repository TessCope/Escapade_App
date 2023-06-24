const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  nom: String,
  prenom: String,
  email: String,
  password: String,
  favoris: [mongoose.Schema.Types.ObjectId],
  reservations: [mongoose.Schema.Types.ObjectId],
  hebergements: [mongoose.Schema.Types.ObjectId]
});

module.exports = mongoose.model('User', UserSchema);
