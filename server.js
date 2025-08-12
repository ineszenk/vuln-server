// Importer les modules nécessaires
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();  // Base de données SQLite
const cookieParser = require('cookie-parser'); // pour parser les cookies
const bodyParser = require('body-parser'); // pour parser le body
const csrf = require('csurf'); // ✅ import manquant


// Créer une instance de l'application Express
const app = express();


// Définir le port d'écoute
const PORT = 3000;

// Middleware pour analyser les requêtes JSON
app.use(express.json());

app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: false }));

const csrfProtection = csrf({ cookie: true });


// Middleware pour envoyer le token à chaque GET
app.use((req, res, next) => {
    if (req.method === 'GET') {
        res.locals.csrfToken = req.csrfToken();
    }
    next();
});


// Créer une base de données en mémoire (vulnérabilité potentielle si elle était persistante)
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'), (err) => {
    if (err) {
        console.error('Erreur lors de la création de la base de données :', err.message);
    } else {
        console.log('Base de données SQLite créée avec succès dans un fichier.');
    }
});

// Créer une table pour stocker des utilisateurs (sans sécurisation des champs)
//db.serialize(() => {
 //   db.run("CREATE TABLE users (name TEXT, age INTEGER)");
//});


// Définir une route GET pour la page d'accueil
app.get('/', (req, res) => {
    res.send('Bienvenue sur le serveur Express!');
});

// Définir une route GET pour une page "hello"
app.get('/hello', (req, res) => {
    res.send('Hello World!');
});

app.get('/form', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

const uploadDir = path.join(__dirname, 'uploads');


// Vulnérabilité : Inclusion de fichier avec un chemin d'accès non sécurisé
app.get('/files/:filename', (req, res) => {
    // Nettoyer filename : supprimer les séquences ../ en début
    let filename = req.params.filename.replace(/^(\.\.(\/|\\|$))+/, '');

    // Construire chemin sécurisé
    const filePath = path.join(uploadDir, filename);

    // Vérifier que le chemin est bien dans uploadDir
    if (!filePath.startsWith(uploadDir)) {
        return res.status(400).send('Accès refusé');
    }

    res.sendFile(filePath, (err) => {
        if (err) {
            res.status(404).send('Fichier non trouvé');
        }
    });
});


// Vulnérabilité : Injection SQL dans une requête non préparée
app.get('/user', (req, res) => {
    const userName = req.query.name;
    const query = `SELECT * FROM users WHERE name = ?`;
    //`SELECT * FROM users WHERE name = 'Paul' OR '1' = '1'`; 
    
    db.all(query, [userName], (err, rows) => {
        if (err) {
            res.status(500).send('Erreur du serveur');
        } else if (rows.length > 0) {
            res.send(`Utilisateur trouvé : ${JSON.stringify(rows)}`);
        } else {
            res.send('Utilisateur non trouvé');
        }
    });
});


const escapeHtml = (unsafe) =>
    unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

// Vulnérabilité : Absence de validation d'entrée sur les requêtes POST
app.post('/data', csrfProtection,  (req, res) => {
    const { name, age } = req.body;
    if (typeof name !== 'string' || !name.trim()) {
        return res.status(400).send("Nom invalide");
    }
    const ageNumber = parseInt(age, 10);
    if (isNaN(ageNumber) || ageNumber < 0 || ageNumber > 120) {
        return res.status(400).send("Âge invalide");
    }

    const trimmedName = name.trim();

    const stmt = db.prepare(`INSERT INTO users (name, age) VALUES (?, ?)`);
    stmt.run(trimmedName, ageNumber, function(err) {
        if (err) {
            return res.status(500).send("Erreur lors de l'insertion en base");
        }
        // Réponse avec échappement HTML pour éviter le XSS
        res.json({ message: `Bonjour ${trimmedName}, vous avez ${ageNumber} ans.` });
    });
    stmt.finalize();
});

// Lancer le serveur
app.listen(PORT, () => {
    console.log(`Serveur en écoute sur le port ${PORT}`);
});
