const User = require('../models/User');
const argon2 = require('argon2');

exports.signUp = async (req, res) => {
    const { email, motDePasse, prenom, nom } = req.body;

    // Check si identifiant deja utilise
    let user = await User.findOne({ email });

    if (user) {
        return res.status(400).json({ message: 'Identifiant déjà utilisé' });
    }

    // Encryptage
    const hashedPassword = await argon2.hash(motDePasse);

    // Create User
    user = new User({
        prenom,
        nom,
        email,
        motDePasse: hashedPassword
    });

    await user.save();
    res.status(201).json({ message: 'Vous êtes maintenant inscrit a Escapade. Bienvenue', user });
};

exports.signIn = async (req, res) => {
    const { email, motDePasse } = req.body;

    // Cherche lidentifiant dans la DB (email)
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(401).json({ error: 'Cet identifiant est inexistant ' });
    }

    // Vérification du password/encryption sur la DB
    const isMatch = await argon2.verify(user.password, motDePasse);

    if (!isMatch) {
        return res.status(401).json({ error: 'Mot de passe invalide' });
    }

    // Succes
    res.status(200).json({ message: 'Bienvenue', user });
};
