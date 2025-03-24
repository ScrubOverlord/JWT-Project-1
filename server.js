const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const moment = require('moment');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies

// SQLite database setup
const DB_FILENAME = 'totally_not_my_privateKeys.db';
const db = new sqlite3.Database(DB_FILENAME);

// Create the keys table if it doesn't exist
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )`);
});

// Function to serialize a private key to PEM format
function serializePrivateKey(privateKey) {
    return privateKey.export({
        type: 'pkcs1',
        format: 'pem'
    });
}

// Function to deserialize a private key from PEM format
function deserializePrivateKey(pemKey) {
    return crypto.createPrivateKey({
        key: pemKey,
        format: 'pem',
        type: 'pkcs1'
    });
}

// Function to generate RSA key pair
function generateRSAKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // RSA key length
    });
    return { privateKey, publicKey };
}

// Function to create a JWK from public key
function createJWK(publicKey, kid, expiration) {
    const keyObject = publicKey.export({ format: 'jwk' });

    return {
        alg: 'RS256',
        kty: 'RSA',
        n: keyObject.n,
        e: keyObject.e,
        kid: String(kid),
        exp: expiration,
    };
}

// Function to store a key in the database
function storeKey(privateKey, expiryTime) {
    return new Promise((resolve, reject) => {
        const serializedKey = serializePrivateKey(privateKey);
        const stmt = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?)');
        stmt.run(serializedKey, expiryTime, function(err) {
            if (err) {
                reject(err);
            } else {
                resolve(this.lastID); // Return the kid (auto-incremented ID)
            }
        });
        stmt.finalize();
    });
}

// Function to retrieve a key from the database by expiry status
function getKey(expired = false) {
    return new Promise((resolve, reject) => {
        const currentTime = Math.floor(Date.now() / 1000);
        let query;
        
        if (expired) {
            // Get an expired key
            query = 'SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1';
        } else {
            // Get a valid key
            query = 'SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1';
        }
        
        db.get(query, [currentTime], (err, row) => {
            if (err) {
                reject(err);
            } else if (!row) {
                reject(new Error(`No ${expired ? 'expired' : 'valid'} key found`));
            } else {
                const privateKey = deserializePrivateKey(row.key);
                resolve({
                    kid: row.kid,
                    privateKey: privateKey,
                    exp: row.exp
                });
            }
        });
    });
}

// Function to get all valid keys from the database
function getAllValidKeys() {
    return new Promise((resolve, reject) => {
        const currentTime = Math.floor(Date.now() / 1000);
        const query = 'SELECT kid, key, exp FROM keys WHERE exp > ?';
        
        db.all(query, [currentTime], (err, rows) => {
            if (err) {
                reject(err);
            } else {
                const keys = rows.map(row => {
                    const privateKey = deserializePrivateKey(row.key);
                    const publicKey = crypto.createPublicKey(privateKey);
                    return createJWK(publicKey, row.kid, row.exp);
                });
                resolve(keys);
            }
        });
    });
}

// Initialize the database with at least one expired and one valid key
async function initializeKeys() {
    try {
        // Check if we already have keys
        const currentTime = Math.floor(Date.now() / 1000);
        const countQuery = 'SELECT COUNT(*) as count FROM keys';
        
        const keyCount = await new Promise((resolve, reject) => {
            db.get(countQuery, [], (err, row) => {
                if (err) reject(err);
                else resolve(row.count);
            });
        });
        
        if (keyCount === 0) {
            console.log("Initializing database with keys...");
            
            // Create and store an expired key
            const expiredPair = generateRSAKeyPair();
            const expiredTime = Math.floor(Date.now() / 1000) - 300; // 5 minutes ago
            await storeKey(expiredPair.privateKey, expiredTime);
            
            // Create and store a valid key
            const validPair = generateRSAKeyPair();
            const validTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
            await storeKey(validPair.privateKey, validTime);
            
            console.log("Keys initialized successfully!");
        }
    } catch (error) {
        console.error("Error initializing keys:", error);
    }
}

// Endpoint to return the JWKS (JSON Web Key Set)
app.get('/.well-known/jwks.json', async (req, res) => {
    try {
        const validKeys = await getAllValidKeys();
        
        const jwks = { 
            keys: validKeys.map(key => ({
                kty: 'RSA',
                kid: String(key.kid),
                alg: 'RS256',
                use: 'sig',
                n: key.n,
                e: key.e,
            }))
        };
        
        res.json(jwks);
    } catch (error) {
        console.error("Error retrieving keys:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Endpoint to issue JWT token
app.post('/auth', async (req, res) => {
    const { expired } = req.query;
    
    try {
        const isExpired = expired === 'true';
        const keyData = await getKey(isExpired);
        
        // Generate the token expiry time
        let tokenExp;
        if (isExpired) {
            tokenExp = Math.floor(Date.now() / 1000) - 300; // 5 minutes ago
        } else {
            tokenExp = Math.floor(Date.now() / 1000) + 300; // 5 minutes from now
        }
        
        const token = jwt.sign(
            {
                iss: 'my-app',
                sub: 'user-authentication',
                user: 'test_user',
                iat: Math.floor(Date.now() / 1000), // Issued at time
                exp: tokenExp, // Expiry time
            },
            keyData.privateKey,
            { algorithm: 'RS256', keyid: String(keyData.kid) }
        );
        
        res.json({ token });
    } catch (error) {
        console.error("Error generating token:", error);
        
        // If no key with the requested expiry status exists, generate one
        try {
            const { privateKey, publicKey } = generateRSAKeyPair();
            const isExpired = expired === 'true';
            
            let expiryTime;
            if (isExpired) {
                expiryTime = Math.floor(Date.now() / 1000) - 300; // 5 minutes ago
            } else {
                expiryTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
            }
            
            const kid = await storeKey(privateKey, expiryTime);
            
            // Generate the token expiry time
            let tokenExp;
            if (isExpired) {
                tokenExp = Math.floor(Date.now() / 1000) - 300; // 5 minutes ago
            } else {
                tokenExp = Math.floor(Date.now() / 1000) + 300; // 5 minutes from now
            }
            
            const token = jwt.sign(
                {
                    iss: 'my-app',
                    sub: 'user-authentication',
                    user: 'test_user',
                    iat: Math.floor(Date.now() / 1000), // Issued at time
                    exp: tokenExp, // Expiry time
                },
                privateKey,
                { algorithm: 'RS256', keyid: String(kid) }
            );
            
            res.json({ token });
        } catch (genError) {
            console.error("Error generating new key:", genError);
            res.status(500).json({ error: "Internal Server Error" });
        }
    }
});

// Basic authentication simulation (for the test client)
app.post('/auth', (req, res, next) => {
    // Check for Basic Auth
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
        // Process basic auth (not actually validating in this mock)
        return next();
    }
    
    // Check for JSON body with username/password
    if (req.body && req.body.username && req.body.password) {
        // Process username/password (not actually validating in this mock)
        return next();
    }
    
    // If neither authentication method is present, proceed anyway for this mock
    next();
});

// Handle unsupported HTTP methods for the given endpoints
app.all("/.well-known/jwks.json", (req, res) => {
    if (req.method !== 'GET') {
        res.status(405).json({ error: "Method Not Allowed" });
    }
});

app.all("/auth", (req, res) => {
    if (req.method !== 'POST') {
        res.status(405).json({ error: "Method Not Allowed" });
    }
});

// Start the server
async function startServer() {
    await initializeKeys();
    
    const port = 8080;
    app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
        console.log(`Database file: ${DB_FILENAME}`);
    });
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Database connection closed');
        process.exit(0);
    });
});

startServer().catch(console.error);