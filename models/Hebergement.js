const mongoose = require('mongoose');

const HebergementSchema = new mongoose.Schema({
  idHebergement: mongoose.Schema.Types.ObjectId,
  titre: String,
  description: String,
  imageSrc: String,
  categorie: {
    type: String,
    enum : ['Chalet','Appartement','Maison'],
  },
  nbChambres: Number,
  nbSalleBains: Number,
  nbPersonneMax: Number,
   localisation: {
    adresse: String,
    ville: String,
    pays: String,
    codePostal: String,
  },
  prix: Number,
  user: mongoose.Schema.Types.ObjectId,
  reservations: [mongoose.Schema.Types.ObjectId],
  animalAccepte: Boolean
});

module.exports = mongoose.model('Hebergement', HebergementSchema);
