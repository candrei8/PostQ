import * as crypto from 'crypto';
import * as CryptoJS from 'crypto-js';

// RSA key generation
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024,
});

// ECDH
const ecdh = crypto.createECDH('prime256v1');

// DES cipher
const desCipher = crypto.createCipheriv('des-ede3-cbc', key, iv);

// MD5 hash
const md5Hash = crypto.createHash('md5').update('data').digest('hex');
const sha1Hash = crypto.createHash('sha1').update('data').digest('hex');

// Weak random
const random = Math.random();
const randomInt = Math.floor(Math.random() * 100);

// CryptoJS
const rc4Encrypted = CryptoJS.RC4.encrypt(data, key);
const ecbMode = CryptoJS.mode.ECB;
const blowfish = CryptoJS.Blowfish.encrypt(data, key);

// WebCrypto RSA
const webRsaKey = await crypto.subtle.generateKey({
    name: "RSA-OAEP",
    modulusLength: 2048,
}, true, ["encrypt", "decrypt"]);

// AES-128
const aes128 = crypto.createCipheriv('aes-128-cbc', key, iv);

// node-rsa
import NodeRSA from 'node-rsa';
