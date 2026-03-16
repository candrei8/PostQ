import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.DESKeySpec

fun generateWeakKeys() {
    val rsaGen = KeyPairGenerator.getInstance("RSA")
    rsaGen.initialize(1024)
    val rsaKeyPair = rsaGen.generateKeyPair()

    val ecGen = KeyPairGenerator.getInstance("EC")
    val dsaGen = KeyPairGenerator.getInstance("DSA")
    val dhGen = KeyPairGenerator.getInstance("DH")

    val desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
    val md5 = MessageDigest.getInstance("MD5")
    val sha1 = MessageDigest.getInstance("SHA-1")

    val weakRandom = java.util.Random()
    val rc4Cipher = Cipher.getInstance("RC4")
    val blowfishCipher = Cipher.getInstance("Blowfish")
}
