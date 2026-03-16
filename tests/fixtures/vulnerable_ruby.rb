require 'openssl'
require 'digest'

# RSA key generation
rsa_key = OpenSSL::PKey::RSA.new(1024)
rsa_key2 = OpenSSL::PKey::RSA.generate(2048)

# ECC key
ec_key = OpenSSL::PKey::EC.new("prime256v1")

# DSA key
dsa_key = OpenSSL::PKey::DSA.new(2048)

# DH key
dh = OpenSSL::PKey::DH.new(2048)

# DES cipher
des = OpenSSL::Cipher::DES.new("CBC")
des3 = OpenSSL::Cipher.new("DES-EDE3-CBC")

# Weak hashes
md5 = Digest::MD5.hexdigest("data")
sha1 = Digest::SHA1.hexdigest("data")

# Weak random
random_val = rand(100)

# RC4
rc4 = OpenSSL::Cipher::RC4.new

# SSL config
ctx = OpenSSL::SSL::SSLContext.new("SSLv3")
ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE

# AES-128
aes128 = OpenSSL::Cipher.new("AES-128-CBC")
