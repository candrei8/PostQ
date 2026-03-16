/**
 * Fixture: Java code with quantum-vulnerable cryptography.
 * Every usage here should trigger at least one finding.
 */

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class VulnerableCrypto {

    // RSA key generation — quantum vulnerable
    public void generateRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        var keyPair = kpg.generateKeyPair();
    }

    // RSA with small key
    public void generateSmallRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        var keyPair = kpg.generateKeyPair();
    }

    // DSA — quantum vulnerable
    public void generateDSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(2048);
    }

    // MD5 — broken hash
    public byte[] hashMD5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    // SHA-1 — broken hash
    public byte[] hashSHA1(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    // DES — broken cipher
    public void encryptDES() throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    // AES in ECB mode — insecure
    public void encryptAESECB() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    // Weak random
    public int weakRandom() {
        Random random = new Random();
        return random.nextInt();
    }
}
