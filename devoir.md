## Objectifs

**Sécurisation du Code Source** : Modifiez le code source de l’application afin que Semgrep ne détecte plus de vulnérabilités.

**Injections SQL** : Appliquez les modifications nécessaires pour éliminer toutes les vulnérabilités d’injection SQL.

**Path Traversal** : Modifiez le code de manière à corriger les failles de path traversal présentes.

**Aucune autre vulnérabilité** : Veillez à ce qu'aucune autre vulnérabilité ne soit relevée par Semgrep.

**Documentation** : Documentez toutes les modifications effectuées dans un fichier texte ou un PDF, en expliquant les solutions appliquées pour sécuriser le code contre les vulnérabilités identifiées.



## 1 . Injections SQL :

**Problème détecté :**  
Deux requêtes vulnérables aux injections concaténant directement des paramètres utilisateur dans la requête SQL.

**Solutions :**

- Ajout du placeholder “?” pour que les paramètres ne soient pas concaténées directement dans la requête

```json
app.get('/user', (req, res) => {
    const userName = req.query.name;
    const query = `SELECT * FROM users WHERE name = ?`;
    
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
```

- Validation des entrées name et age

- Ajout de placeholders “?” pour que les paramètres ne soient pas concaténées directement dans la requête

- Preparation des requêtes pour séparer clairement la structure SQL et les données paramètres (prepare, run, finalize)

```json
app.post('/data', csrfProtection, (req, res) => {
    const { name, age } = req.body;

    // Validation simple des entrées
    if (typeof name !== 'string' || !name.trim()) {
        return res.status(400).send("Nom invalide");
    }
    const ageNumber = parseInt(age, 10);
    if (isNaN(ageNumber) || ageNumber < 0 || ageNumber > 120) {
        return res.status(400).send("Âge invalide");
    }

    // Requête préparée pour éviter l'injection SQL
    const stmt = db.prepare(`INSERT INTO users (name, age) VALUES (?, ?)`);
    stmt.run(name.trim(), ageNumber, function(err) {
        if (err) {
            return res.status(500).send("Erreur lors de l'insertion en base");
        }
        res.send(`Bonjour ${name.trim()}, vous avez ${ageNumber} ans.`);
    });
    stmt.finalize();
});

```

## 2. Path Traversal :

 ❯❱ javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
   Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Solutions :**

Dans un premier temps, utilisation de  **`path.basename()` pour** récupèrer uniquement le nom de fichier et pas un chemin complet qui pourrait permettre de remonter dans l’arborescence  (`../`) 

```json
app.get('/files/:filename', (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(uploadDir, filename);
    res.sendFile(filePath, (err) => {
        if (err) res.status(404).send('Fichier non trouvé');
    });
});
```

Cependant, Semgrep détectait toujours la vulnérabilité de path traversal, je rajoute ce check supplémentaire :

 

```json
   const normalizedPath = path.normalize(filePath);

    if (!normalizedPath.startsWith(uploadDir)) {
        return res.status(400).send('Accès refusé');
    }
```

Semgrep détecte encore la vulnérabilité, je comprends qu’il faut être strict et explicite je rajoute donc une regex qui retire toute les séquences en début de chaîne pour supprimer toutes tentative de remonter dans l’arborescence :

```json
app.get('/files/:filename', (req, res) => {
    let filename = req.params.filename.replace(/^(\.\.(\/|\\|$))+/, '');

    const filePath = path.join(uploadDir, filename);

    if (!filePath.startsWith(uploadDir)) {
        return res.status(400).send('Accès refusé');
    }

    res.sendFile(filePath, (err) => {
        if (err) {
            res.status(404).send('Fichier non trouvé');
        }
    });
});
```

Autre vulnerabilités :      

## 3. CRSF

❱ javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage
       A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your  server.js

**Solutions**:

Ajout d’une  middleware dans le server pour être protégé contre les attaques Cross site request forgery. J’ajoute la middleware uniquement sur les routes qui modifient des données pour éviter qu’un autre site puisse exploiter la session ouverte de l’utilisateur. Avec le middleware, la creation de token unique permet la protection de l’utilisateur contre une attaque cross site request forgery. 

```json
const csrfProtection = csrf({ cookie: true });

app.post('/data', csrfProtection,  (req, res) => {...}

```

## 4. XSS 

```json
❯❱ javascript.express.security.audit.xss.direct-response-write.direct-response-write
Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.
```

Utilisation de res.json au lieu de res.send pour viter une réponse en javascript pur ou html qui pourrait être rendu directement : 

```json
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
        res.json({ message: `Bonjour ${trimmedName}, vous avez ${ageNumber} ans.` });
    });
    stmt.finalize();
});

```