// Importer les modules nécessaires
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();  // Base de données SQLite

// Créer une instance de l'application Express
const app = express();

// Définir le port d'écoute
const PORT = 3000;

// Middleware pour analyser les requêtes JSON
app.use(express.json());

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

const uploadDir = path.join(__dirname, 'uploads');


// Vulnérabilité : Inclusion de fichier avec un chemin d'accès non sécurisé
app.get('/files/:filename', (req, res) => {
    console.log("/files/:filename")

    const filename = req.params.filename;

    const filePath = path.join(uploadDir, filename);

    const normalizedPath = path.normalize(filePath);

    // Envoyer le fichier
    res.sendFile(normalizedPath, (err) => {
        if (err) {
            res.status(404).send('Fichier non trouvé');
        }
    });
});

// Vulnérabilité : Injection SQL dans une requête non préparée
app.get('/user', (req, res) => {
    const userName = req.query.name;
    const query = `SELECT * FROM users WHERE name = '${userName}'`;  // Requête non préparée
    //`SELECT * FROM users WHERE name = 'Paul' OR '1' = '1'`; 
    
    db.all(query, [], (err, rows) => {
        if (err) {
            res.status(500).send('Erreur du serveur');
        } else if (rows.length > 0) {
            res.send(`Utilisateur trouvé : ${JSON.stringify(rows)}`);
        } else {
            res.send('Utilisateur non trouvé');
        }
    });
});

// Vulnérabilité : Absence de validation d'entrée sur les requêtes POST
app.post('/data', (req, res) => {
    const { name, age } = req.body;
    db.run(`INSERT INTO users (name, age) VALUES ('${name}', ${age})`);  // Requête vulnérable aux injections
    res.send(`Bonjour ${name}, vous avez ${age} ans.`);
});

// Lancer le serveur
app.listen(PORT, () => {
    console.log(`Serveur en écoute sur le port ${PORT}`);
});
