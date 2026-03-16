import Security
import CommonCrypto
import CryptoKit

func generateWeakKey() {
    var publicKey, privateKey: SecKey?
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 1024
    ]
    SecKeyGeneratePair(attributes as CFDictionary, &publicKey, &privateKey)

    let md5Hash = Insecure.MD5.hash(data: data)
    let sha1Hash = Insecure.SHA1.hash(data: data)

    let ecKey = P256.Signing.PrivateKey()
    let random = arc4random()

    var result = [UInt8](repeating: 0, count: 16)
    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), 0, key, kCCKeySizeAES128, iv, data, dataLength, &result, result.count, &numBytesEncrypted)
}
