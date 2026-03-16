import 'package:pointycastle/pointycastle.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'dart:math';

void generateWeakKeys() {
  // RSA key generation
  final keyGen = RSAKeyGenerator();
  final params = RSAKeyGeneratorParameters(BigInt.from(65537), 1024, 12);

  // ECC
  final ecParams = ECDomainParameters('prime256v1');
  final ecKeyGen = ECKeyGenerator();

  // ECDSA
  final signer = ECDSASigner();

  // DSA
  final dsaSigner = DSASigner();

  // DES
  final des = DESEngine();
  final des3 = DESedeEngine();

  // MD5
  final md5Hash = md5.convert([1, 2, 3]);
  final md5Digest = MD5Digest();

  // SHA-1
  final sha1Hash = sha1.convert([1, 2, 3]);
  final sha1Digest = SHA1Digest();

  // ECB mode
  final ecb = ECBBlockCipher(AESEngine());

  // Weak random
  final rng = Random();

  // encrypt package
  final encrypter = Encrypter(AES(key));

  // SecurityContext
  final ctx = SecurityContext();
}
