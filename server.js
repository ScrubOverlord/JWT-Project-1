const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const moment = require('moment');

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies

// In-memory storage for keys
let keys = [];
let kid = 0;

// Function to generate RSA key pair
function generateRSAKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // RSA key length
    });
    return { privateKey, publicKey };
}

// Function to create a JWK
function newJWK(publicKey) {
    kid += 1;
    const keyObject = publicKey.export({ format: 'jwk' });

    return {
        alg: 'RS256',
        kty: 'RSA',
        n: keyObject.n,
        e: keyObject.e,
        kid: String(kid),
        exp: moment().add(5, 'minutes').toISOString(), // Set expiration date for 5 minutes
    };
}

// Function to check if a key is expired
function isKeyExpired(key) {
    return moment().isAfter(moment(key.exp));
}

// Function to generate JWT
function generateJWT(isExpired) {
    let numTime = 5 * 60 * 1000; // 5 minutes in milliseconds

    if (isExpired) {
        numTime = -numTime; // make the token expired
    }

    const { privateKey, publicKey } = generateRSAKeyPair();
    const jwk = newJWK(publicKey);

    const token = jwt.sign(
        {
            iss: 'my-app',
            sub: 'user-authentication',
            user: 'test_user',
            iat: Math.floor(Date.now() / 1000), // Issued at time
            exp: Math.floor((Date.now() + numTime) / 1000), // Expiry time
        },
        privateKey,
        { algorithm: 'RS256', keyid: jwk.kid }
    );

    // Add the new key to the keys array
    keys.push(jwk);

    return { token, publicKey };
}

// Endpoint to return the JWKS (JSON Web Key Set)
app.get('/.well-known/jwks.json', (req, res) => {
    const jwks = { keys: [] };

    // Filter out expired keys from the JWKS
    for (const key of keys) {
        if (!isKeyExpired(key)) {
            jwks.keys.push({
                kty: 'RSA',
                kid: key.kid,
                alg: 'RS256',
                use: 'sig',
                n: key.n,
                e: key.e,
            });
        }
    }

    // Return the filtered JWKS
    res.json(jwks);
});

// Endpoint to issue JWT token
app.post('/auth', (req, res) => {
    const { expired } = req.query;

    let token;
    let publicKey;

    if (expired === 'true') {
        ({ token, publicKey } = generateJWT(true)); // Generate expired JWT
    } else {
        ({ token, publicKey } = generateJWT(false)); // Generate valid JWT
    }

    // Return the token in the response
    res.json({ token });
});

// Handle unsupported HTTP methods for the given endpoints
app.all("/.well-known/jwks.json", (req, res) => {
    res.status(405).json({ error: "Method Not Allowed" });
});

app.all("/auth", (req, res) => {
    res.status(405).json({ error: "Method Not Allowed" });
});

// Start the server
const port = 8080;
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
