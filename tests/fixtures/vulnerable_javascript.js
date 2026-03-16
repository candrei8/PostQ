/**
 * Fixture: JavaScript code with quantum-vulnerable cryptography.
 * Every usage here should trigger at least one finding.
 */

const crypto = require('crypto');
const CryptoJS = require('crypto-js');

// MD5 hash — broken
const md5Hash = crypto.createHash('md5').update('data').digest('hex');

// SHA-1 hash — broken
const sha1Hash = crypto.createHash('sha1').update('data').digest('hex');

// DES cipher — broken
const desCipher = crypto.createCipher('des', 'password');

// RSA key generation — quantum vulnerable
crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// EC key generation — quantum vulnerable
crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
});

// DiffieHellman — quantum vulnerable
const dh = crypto.createDiffieHellman(2048);

// CryptoJS MD5 — broken
const hash = CryptoJS.MD5('message');

// CryptoJS DES — broken
const encrypted = CryptoJS.DES.encrypt('message', 'key');

// Weak random for crypto
const key = Math.random().toString(36);
