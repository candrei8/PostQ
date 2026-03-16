import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.DESKeySpec

object VulnerableCode {
  def generateWeakKeys(): Unit = {
    val rsaGen = KeyPairGenerator.getInstance("RSA")
    rsaGen.initialize(1024)
    val rsaKeyPair = rsaGen.generateKeyPair()

    val ecGen = KeyPairGenerator.getInstance("EC")
    val dsaGen = KeyPairGenerator.getInstance("DSA")
    val dhGen = KeyPairGenerator.getInstance("DH")

    val desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
    val desede = Cipher.getInstance("DESede/CBC/PKCS5Padding")

    val md5 = MessageDigest.getInstance("MD5")
    val sha1 = MessageDigest.getInstance("SHA-1")

    val weakRandom = new scala.util.Random()
    val rc4Cipher = Cipher.getInstance("RC4")
    val blowfishCipher = Cipher.getInstance("Blowfish")

    val sslCtx = javax.net.ssl.SSLContext.getInstance("TLS")
  }
}
