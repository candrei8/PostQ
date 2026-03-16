<?php
// RSA key generation
$config = array(
    "private_key_bits" => 1024,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
);
$key = openssl_pkey_new($config);
$pubKey = openssl_pkey_get_public($cert);

// Weak hashing
$hash = md5("password");
$sha = sha1("data");

// DES encryption
$encrypted = openssl_encrypt($data, "DES-ECB", $key);
$encrypted3 = openssl_encrypt($data, "des-ede3-cbc", $key);

// Weak random
$random = mt_rand(0, 100);
$r2 = rand(1, 50);

// mcrypt (deprecated)
$enc = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);

// OpenSSL signing
openssl_sign($data, $signature, $privKey);

// Weak TLS
stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_0);
?>
