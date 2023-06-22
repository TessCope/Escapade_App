import React, { useState } from "react";
import { FaGlobe } from "react-icons/fa";
import { BiSearch, BiUser, BiMenu } from "react-icons/bi";
import logo from "../images/escapade.png";
import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap/dist/js/bootstrap.bundle.min.js";
import Modal from "react-modal";
import axios from "axios";

Modal.setAppElement("#root");

function Header() {
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [isLoginPopupOpen, setIsLoginPopupOpen] = useState(false);
  const [isEscapadePopupOpen, setIsEscapadePopupOpen] = useState(false);
  const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
  const passwordRegex =
    /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

  const handleInscriptionClick = (event) => {
    event.preventDefault();
    setIsLoginPopupOpen(false);
    setIsEscapadePopupOpen(false);
    setIsPopupOpen(true);
  };

  const handleLoginClick = (event) => {
    event.preventDefault();
    setIsPopupOpen(false);
    setIsEscapadePopupOpen(false);
    setIsLoginPopupOpen(true);
  };

  const handleEscapadeClick = (event) => {
    event.preventDefault();
    setIsPopupOpen(false);
    setIsLoginPopupOpen(false);
    setIsEscapadePopupOpen(true);
  };

  const handleLanguageClick = (event) => {
    event.preventDefault();
    ////////////////////////////////////////////////////////////////////
    // Faire une action pour changer la langue
  };

  const [formValues, setFormValues] = useState({
    prenom: "",
    nom: "",
    email: "",
    motDePasse: "",
    repete_passe: "",
  });

  const [connexionFormValues, setConnexionFormValues] = useState({
    loginEmail: "",
    loginPassword: "",
  });

  const [escapadeFormValues, setEscapadeFormValues] = useState({
    titre: "",
    description: "",
    categorie: "",
    adresse: "",
    ville: "",
    codepostal: "",
    pays: "",
    nbChambres: "",
    nbSallesDeBain: "",
    nbPersonnesMax: "",
    animaux: "",
    photos: "",
    prix: "",
    image: "",
  });

  const [isConnexionFormValid, setIsConnexionFormValid] = useState(false);
  const [connexionFormErrors, setConnexionFormErrors] = useState({});

  const [isFormValid, setIsFormValid] = useState(false);
  const [formErrors, setFormErrors] = useState({});

  const [isEscapadeFormValid, setIsEscapadeFormValid] = useState(false);
  const [escapadeFormErrors, setEscapadeFormErrors] = useState({});

  const validateForm = () => {
    const errors = {};

    // Vérification du mot de passe en testant la conformité à la passwordRegex
    if (!passwordRegex.test(formValues.motDePasse)) {
      errors.motDePasse =
        "Le mot de passe doit comporter au moins 8 caractères, dont au moins une majuscule, une minuscule, un chiffre et un caractère spécial";
    }

    // Vérification de l'égalité entre le mot de passe et sa répétition
    if (formValues.motDePasse !== formValues.repete_passe) {
      errors.repete_passe = "Les mots de passe ne correspondent pas";
    }

    // Vérification des autres champs du formulaire d'inscription
    if (formValues.prenom.trim() === "") {
      errors.prenom = "Veuillez renseigner ce champ";
    }

    if (formValues.nom.trim() === "") {
      errors.nom = "Veuillez renseigner ce champ";
    }

    if (formValues.email.trim() === "") {
      errors.email = "Veuillez renseigner ce champ";
    }

    if (formValues.motDePasse.trim() === "") {
      errors.motDePasse = "Veuillez renseigner ce champ";
    }

    if (formValues.repete_passe.trim() === "") {
      errors.repete_passe = "Veuillez renseigner ce champ";
    }

    return errors;
  };

  const handleSubmit = (event) => {
    event.preventDefault();

    // Validation du formulaire
    const formErrors = validateForm();
    setFormErrors(formErrors);

    // Vérification de la validité du formulaire
    const isValid = Object.keys(formErrors).length === 0;
    setIsFormValid(isValid);

    if (isValid) {
      setIsPopupOpen(false); //// changer ça quand on aura la réponse du serveur
      // Soumission du formulaire
      axios
        .post("/url-de-soumission", formValues)
        .then((response) => {
          // Traitement de la réponse du serveur en cas de succès
          console.log("Réponse du serveur :", response.data);
          // Réinitialisation des valeurs du formulaire
          setFormValues({
            prenom: "",
            nom: "",
            email: "",
            motDePasse: "",
            repete_passe: "",
          });
          // Fermeture de la popup
        })
        .catch((error) => {
          // Traitement de l'erreur en cas d'échec de la soumission
          console.error("Erreur lors de la soumission du formulaire :", error);
        });
    }
  };

  const validateConnexionForm = () => {
    const { email, motDePasse } = connexionFormValues;

    const errors = {};

    if (!email || email.trim() === "") {
      errors.email = "Veuillez renseigner ce champ";
    } else if (!emailRegex.test(email)) {
      errors.email = "Veuillez entrer une adresse email valide.";
    }

    if (!motDePasse || motDePasse.trim() === "") {
      errors.motDePasse = "Veuillez renseigner ce champ";
    } else if (!passwordRegex.test(motDePasse)) {
      errors.motDePasse =
        "Il semble que le mot de passe ne soit pas dans un format valide. Veuillez réessayer.";
      setConnexionFormValues({
        email: email,
        motDePasse: "",
      });
    }

    return errors;
  };

  const handleConnexionSubmit = (event) => {
    event.preventDefault();

    // Validation du formulaire de connexion
    const connexionFormErrors = validateConnexionForm();
    setConnexionFormErrors(connexionFormErrors);

    // Vérification de la validité du formulaire de connexion
    const isValid = Object.keys(connexionFormErrors).length === 0;
    setIsConnexionFormValid(isValid);

    if (isValid) {
      // Soumission du formulaire de connexion
      // Effectuer ici les actions nécessaires (par exemple, l'appel à une API)
      console.log("Formulaire de connexion soumis avec succès");
      // Réinitialisation des valeurs du formulaire de connexion
      setConnexionFormValues({
        loginEmail: "",
        loginPassword: "",
      });
      ///////////////////////////////////////////////////////
      /// changer ça quand on aura la réponse du serveur
      // Fermeture du Modal de connexion
      setIsLoginPopupOpen(false);
    }
  };

  const validateEscapadeForm = () => {
    const {
      titre,
      description,
      pays,
      ville,
      adresse,
      codepostal,
      nbChambres,
      nbSallesDeBain,
      nbPersonnesMax,
      prix,
      photos,
    } = escapadeFormValues;

    const errors = {};

    if (escapadeFormValues.titre.trim() === "") {
      errors.titre = "Veuillez renseigner ce champ";
    }

    if (escapadeFormValues.description.trim() === "") {
      errors.description = "Veuillez renseigner ce champ";
    }

    if (escapadeFormValues.pays.trim() === "") {
      errors.pays = "Veuillez renseigner ce champ";
    }

    if (escapadeFormValues.ville.trim() === "") {
      errors.ville = "Veuillez renseigner ce champ";
    }

    if (escapadeFormValues.adresse.trim() === "") {
      errors.adresse = "Veuillez renseigner ce champ";
    }

    if (escapadeFormValues.codepostal.trim() === "") {
      errors.codepostal = "Veuillez renseigner ce champ";
    }

    if (escapadeFormValues.prix.trim() === "") {
      errors.prix = "Veuillez renseigner ce champ";
    } else if (
      !/^[0-9]+$/.test(escapadeFormValues.prix) ||
      escapadeFormValues.prix < 0
    ) {
      errors.prix = "Veuillez entrer un nombre positif";
    }

    if (escapadeFormValues.nbChambres.trim() === "") {
      errors.nbChambres = "Veuillez renseigner ce champ";
    } else if (
      !/^[0-9]+$/.test(escapadeFormValues.nbChambres) ||
      escapadeFormValues.nbChambres < 0
    ) {
      errors.nbChambres = "Veuillez entrer un nombre positif";
    }

    if (escapadeFormValues.nbSallesDeBain.trim() === "") {
      errors.nbSallesDeBain = "Veuillez renseigner ce champ";
    } else if (
      !/^[0-9]+$/.test(escapadeFormValues.nbSallesDeBain) ||
      escapadeFormValues.nbSallesDeBain < 0
    ) {
      errors.nbSallesDeBain = "Veuillez entrer un nombre positif";
    }

    if (escapadeFormValues.nbPersonnesMax.trim() === "") {
      errors.nbPersonnesMax = "Veuillez renseigner ce champ";
    } else if (
      !/^[0-9]+$/.test(escapadeFormValues.nbPersonnesMax) ||
      escapadeFormValues.nbPersonnesMax < 0
    ) {
      errors.nbPersonnesMax = "Veuillez entrer un nombre positif";
    }

    if (escapadeFormValues.photos === "") {
      errors.photos = "Veuillez renseigner ce champ";
    }

    return errors;
  };

  const handleEscapadeSubmit = (event) => {
    event.preventDefault();

    // Validation du formulaire d'escapade
    const escapadeFormErrors = validateEscapadeForm();
    setEscapadeFormErrors(escapadeFormErrors);

    // Vérification de la validité du formulaire d'escapade
    const isValid = Object.keys(escapadeFormErrors).length === 0;
    setIsEscapadeFormValid(isValid);

    if (isValid) {
      // Soumission du formulaire d'escapade
      // Effectuer ici les actions nécessaires (par exemple, l'appel à une API)
      console.log("Formulaire d'escapade soumis avec succès");
      // Réinitialisation des valeurs du formulaire d'escapade
      setEscapadeFormValues({
        titre: "",
        description: "",
        pays: "",
        ville: "",
        adresse: "",
        dateDebut: "",
        dateFin: "",
        prix: "",
        photos: "",
      });

      ///////////////////////////////////
      // Fermeture du Modal d'escapade
      setIsEscapadePopupOpen(false);
    }
  };

  return (
    <>
      <header className="header">
        <div className="container-fluid">
          <div className="container">
            <div className="row align-items-center">
              <div className="col-md-4">
                {/* Logo */}
                <img src={logo} alt="Logo" className="logoPetit" />
              </div>
              <div className="recherche col-md-4 border border-lightgrey rounded my-2">
                {/* Champ de recherche */}
                <div className="input-group ">
                  <input
                    type="text"
                    placeholder="Rechercher une destination"
                    className="form-control  border border-white rounded-pill"
                  />
                  <div className="input-group-append">
                    <button
                      className="btn btn-dark rounded-circle ms-2 fw-bold my-2 align-items-center justify-content-center "
                      type="button"
                    >
                      <BiSearch />
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-4 menuDroit d-flex justify-content-end">
                {/* Lien "Partez une Escapade" */}
                <a
                  href="/"
                  className="btn btn-link d-flex align-items-center justify-content-end text-decoration-none text-dark ms-auto"
                  onClick={handleEscapadeClick}
                >
                  Partez une Escapade
                </a>

                {/* Bouton pour changer la langue */}
                <button
                  className="globe my-2 pb-2 px-3 border-0 rounded"
                  onClick={handleLanguageClick}
                >
                  <FaGlobe />
                </button>

                {/* Bouton pour se connecter/loguer */}
                <div className="dropdown ">
                  <button
                    className="btn text-decoration-none text-dark dropdown-toggle pb-3 pt-2"
                    type="button"
                    id="loginDropdown"
                    data-bs-toggle="dropdown"
                    aria-expanded="false"
                  >
                    <span className="me-2">
                      <BiMenu />
                    </span>
                    <BiUser />
                  </button>
                  <ul className="dropdown-menu" aria-labelledby="loginDropdown">
                    <li>
                      <a
                        className="dropdown-item inscription-link"
                        href="#"
                        onClick={handleInscriptionClick}
                      >
                        Inscription
                      </a>
                    </li>
                    <li>
                      <a
                        className="dropdown-item"
                        href="#"
                        onClick={handleLoginClick}
                      >
                        Connexion
                      </a>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </header>

      <Modal
        className="custom-modal"
        isOpen={isPopupOpen}
        onRequestClose={() => setIsPopupOpen(false)}
      >
        <form onSubmit={handleSubmit} className="container w-75 px-0">
          <h2>Inscription</h2>
          <div className="form-group">
            <label htmlFor="prenom">Prénom</label>
            <input
              type="text"
              id="prenom"
              className={`form-control ${
                formErrors.prenom ? "is-invalid" : ""
              }`}
              placeholder="Entrez votre prénom"
              value={formValues.prenom}
              onChange={(e) =>
                setFormValues({ ...formValues, prenom: e.target.value })
              }
              required
            />
            {formErrors.prenom && (
              <div className="invalid-feedback">{formErrors.prenom}</div>
            )}
          </div>
          <div className="form-group">
            <label htmlFor="nom">Nom</label>
            <input
              type="text"
              id="nom"
              className={`form-control ${formErrors.nom ? "is-invalid" : ""}`}
              placeholder="Entrez votre nom"
              value={formValues.nom}
              onChange={(e) =>
                setFormValues({ ...formValues, nom: e.target.value })
              }
              required
            />
            {formErrors.nom && (
              <div className="invalid-feedback">{formErrors.nom}</div>
            )}
          </div>
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              className={`form-control ${formErrors.email ? "is-invalid" : ""}`}
              placeholder="Entrez votre email"
              value={formValues.email}
              onChange={(e) =>
                setFormValues({ ...formValues, email: e.target.value })
              }
              required
            />
            {formErrors.email && (
              <div className="invalid-feedback">{formErrors.email}</div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="motDePasse">Mot de passe</label>
            <input
              type="password"
              id="motDePasse"
              className={`form-control ${
                formErrors.motDePasse ? "is-invalid" : ""
              }`}
              placeholder="Entrez votre mot de passe"
              value={formValues.motDePasse}
              onChange={(e) =>
                setFormValues({ ...formValues, motDePasse: e.target.value })
              }
              required
            />
            {formErrors.motDePasse && (
              <div className="invalid-feedback">{formErrors.motDePasse}</div>
            )}
          </div>
          <div className="form-group">
            <label htmlFor="repete_passe">Validation</label>
            <input
              type="password"
              id="repete_passe"
              className={`form-control ${
                formErrors.repete_passe ? "is-invalid" : ""
              }`}
              placeholder="Répétez votre mot de passe"
              value={formValues.repete_passe}
              onChange={(e) =>
                setFormValues({ ...formValues, repete_passe: e.target.value })
              }
              required
            />
            {formErrors.repete_passe && (
              <div className="invalid-feedback">{formErrors.repete_passe}</div>
            )}
          </div>
          <div className="d-flex justify-content-between align-items-center mt-4">
            <button
              type="submit"
              className="btn btn-dark"
              onClick={handleSubmit}
            >
              S'inscrire
            </button>
            <p className="mb-0">
              Déjà inscrit ?{" "}
              <a href="#" onClick={handleLoginClick}>
                Se connecter
              </a>
            </p>
          </div>
        </form>
      </Modal>
      <Modal
        className="custom-modal"
        isOpen={isLoginPopupOpen}
        onRequestClose={() => setIsLoginPopupOpen(false)}
      >
        <form onSubmit={handleConnexionSubmit} className="container w-75">
          <h2>Connexion</h2>
          {/* Login form fields */}
          <div className="form-group">
            <label htmlFor="loginEmail">Email</label>
            <input
              type="email"
              id="loginEmail"
              className={`form-control ${
                connexionFormErrors.email ? "is-invalid" : ""
              }`}
              placeholder="Entrez votre email"
              value={connexionFormValues.email}
              onChange={(e) =>
                setConnexionFormValues({
                  ...connexionFormValues,
                  email: e.target.value,
                })
              }
              required
            />
            {connexionFormErrors.email && (
              <div className="invalid-feedback">
                {connexionFormErrors.email}
              </div>
            )}
          </div>
          <div className="form-group">
            <label htmlFor="loginPassword">Mot de passe</label>
            <input
              type="password"
              id="loginPassword"
              className={`form-control ${
                connexionFormErrors.motDePasse ? "is-invalid" : ""
              }`}
              placeholder="Entrez votre mot de passe"
              value={connexionFormValues.motDePasse}
              onChange={(e) =>
                setConnexionFormValues({
                  ...connexionFormValues,
                  motDePasse: e.target.value,
                })
              }
              required
            />
            {connexionFormErrors.motDePasse && (
              <div className="invalid-feedback">
                {connexionFormErrors.motDePasse}
              </div>
            )}
          </div>
          {/* Login form submit button */}
          <div className="d-flex justify-content-between align-items-center mt-4">
            <button
              type="submit"
              className="btn btn-dark"
              onClick={handleConnexionSubmit}
            >
              Se connecter
            </button>
            <p className="mb-0">
              Pas inscrit ?{" "}
              <a href="#" onClick={handleInscriptionClick}>
                S'inscrire
              </a>
            </p>
          </div>
        </form>
      </Modal>

      <Modal
        scrollable={true}
        className="custom-modal-dialog modal-dialog-scrollable"
        //className="modal-dialog-scrollable"
        // dialogClassName="scrollable-modal"
        // contentClassName="custom-modal-content"
        isOpen={isEscapadePopupOpen}
        onRequestClose={() => setIsEscapadePopupOpen(false)}
      >
        <form
          onSubmit={handleEscapadeSubmit}
          className="container mx-auto my-5 py-1 px-5"
        >
          <h2 className="mb-4">Créer une Escapade</h2>
          {/* Escapade form fields */}
          <div className="form-group">
            <label htmlFor="titre">Titre</label>
            <input
              type="text"
              id="titre"
              className={`form-control  mb-2 ${
                escapadeFormErrors.titre ? "is-invalid" : ""
              }`}
              placeholder="Entrez le titre de votre escapade"
              value={escapadeFormValues.titre}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  titre: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.titre && (
              <div className="invalid-feedback">{escapadeFormErrors.titre}</div>
            )}
          </div>
          <div className="form-group">
            <label htmlFor="description">Description</label>
            <textarea
              id="description"
              className={`form-control mb-2 ${
                escapadeFormErrors.description ? "is-invalid" : ""
              }`}
              placeholder="Entrez la description de votre escapade"
              value={escapadeFormValues.description}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  description: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.description && (
              <div className="invalid-feedback">
                {escapadeFormErrors.description}
              </div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="categorie">Catégorie</label>
            <select id="categorie" className="form-control mb-2">
              <option value="1">Chalet</option>
              <option value="2">Appartement</option>
              <option value="3">Maison</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Adresse</label>
            <input
              type="text"
              id="adresse"
              className={`form-control mb-2 ${
                escapadeFormErrors.adresse ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.adresse}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  adresse: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.adresse && (
              <div className="invalid-feedback">
                {escapadeFormErrors.adresse}
              </div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Ville</label>
            <input
              type="text"
              id="ville"
              className={`form-control mb-2 ${
                escapadeFormErrors.ville ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.ville}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  ville: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.ville && (
              <div className="invalid-feedback">{escapadeFormErrors.ville}</div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Code postal</label>
            <input
              type="text"
              id="codepostal"
              className={`form-control mb-2 ${
                escapadeFormErrors.codepostal ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.codepostal}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  codepostal: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.codepostal && (
              <div className="invalid-feedback">
                {escapadeFormErrors.codepostal}
              </div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Pays</label>
            <input
              type="text"
              id="pays"
              className={`form-control mb-2 ${
                escapadeFormErrors.pays ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.pays}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  pays: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.pays && (
              <div className="invalid-feedback">{escapadeFormErrors.pays}</div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Nombre de chambres</label>
            <input
              type="number"
              id="nbChambres"
              className={`form-control mb-2 ${
                escapadeFormErrors.nbChambres ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.nbChambres}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  nbChambres: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.nbChambres && (
              <div className="invalid-feedback">
                {escapadeFormErrors.nbChambres}
              </div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Nombre de salles de bain</label>
            <input
              type="number"
              id="nbSallesDeBain"
              className={`form-control mb-2 ${
                escapadeFormErrors.nbSallesDeBain ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.nbSallesDeBain}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  nbSallesDeBain: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.nbSallesDeBain && (
              <div className="invalid-feedback">
                {escapadeFormErrors.nbSallesDeBain}
              </div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Nombre de personnes maximum</label>
            <input
              type="number"
              id="nbPersonnesMax"
              className={`form-control mb-2 ${
                escapadeFormErrors.nbPersonnesMax ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.nbPersonnesMax}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  nbPersonnesMax: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.nbPersonnesMax && (
              <div className="invalid-feedback">
                {escapadeFormErrors.nbPersonnesMax}
              </div>
            )}
          </div>

          <div className="form-group">
            <div className="form-check my-3">
              <input
                type="checkbox"
                id="animaux"
                className="form-check-input"
              />
              <label className="form-check-label" htmlFor="animaux">
                Animaux acceptés
              </label>
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Photos</label>
            <input
              type="file"
              id="photos
"
              className={`form-control mb-2 ${
                escapadeFormErrors.photos ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.photos}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  photos: e.target.value,
                })
              }
              required
              multiple
            />
            {escapadeFormErrors.photos && (
              <div className="invalid-feedback">
                {escapadeFormErrors.photos}
              </div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="adresse">Prix par jour</label>
            <input
              type="number"
              id="prix"
              className={`form-control mb-2 ${
                escapadeFormErrors.prix ? "is-invalid" : ""
              }`}
              placeholder="Entrez l'adresse de votre escapade"
              value={escapadeFormValues.prix}
              onChange={(e) =>
                setEscapadeFormValues({
                  ...escapadeFormValues,
                  prix: e.target.value,
                })
              }
              required
            />
            {escapadeFormErrors.prix && (
              <div className="invalid-feedback">{escapadeFormErrors.prix}</div>
            )}
          </div>

          <button
            type="submit"
            className="btn btn-dark mt-3"
            onClick={handleEscapadeSubmit}
          >
            Soumettre
          </button>
        </form>
      </Modal>
    </>
  );
}

export default Header;
