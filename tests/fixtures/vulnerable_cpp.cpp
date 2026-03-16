/**
 * Fixture: C/C++ code with quantum-vulnerable cryptography.
 * Every usage here should trigger at least one finding.
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdlib.h>

void vulnerable_crypto() {
    // RSA key generation — quantum vulnerable
    RSA *rsa_key = RSA_generate_key(2048, RSA_F4, NULL, NULL);

    // MD5 — broken hash
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, "data", 4);

    // SHA-1 — broken hash
    SHA_CTX sha1_ctx;
    SHA1_Init(&sha1_ctx);

    // DES — broken cipher
    DES_key_schedule schedule;
    DES_set_key((DES_cblock *)"12345678", &schedule);

    // EVP MD5 — broken
    const EVP_MD *md5 = EVP_md5();

    // EVP SHA1 — broken
    const EVP_MD *sha1 = EVP_sha1();

    // EVP DES — broken
    const EVP_CIPHER *des_cipher = EVP_des_ecb();

    // Weak random
    int key = rand();
    srand(42);
}
