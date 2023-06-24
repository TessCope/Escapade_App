const mongoose = require('mongoose');

const ReservationSchema = new mongoose.Schema({
  idReservation: mongoose.Schema.Types.ObjectId,
  idClient: mongoose.Schema.Types.ObjectId,
  idHebergement: mongoose.Schema.Types.ObjectId,
  dateDebut: Date,
  dateFin: Date,
  prixTotal: Number,
  dateReservation: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Reservation', ReservationSchema);
