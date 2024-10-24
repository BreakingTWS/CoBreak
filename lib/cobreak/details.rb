module CoBreak
  class Details
    def self.info()
      return "The CoBreak script is an cipher and cryptography tool made with the purpose of facilitating the encryption of data or others, it includes parameters to brute force the hashes through dictionaries"
    end
    def self.dependecias()
      return %w(gcrypt openmp openssl sequel sqlite3)
    end
    def self.date()
      return "2020-5-25"
    end
    def self.cipher()
      return %w(base64 base32 base16 ascii85 cesar binary)
    end
    def self.crypt()
      return %w(MD4 MD5 HALF-MD5 SHA1 SHA2-224 SHA2-256 SHA2-384 SHA2-512 SHA3-224 SHA3-256 SHA3-384 SHA3-512 RIPEMD-160 TIGER-160 DOUBLE-SHA1 BLAKE2S-128 BLAKE2S-160 BLAKE2B-160 BLAKE2S-224 BLAKE2S-256 BLAKE2B-256 BLAKE2B-384 BLAKE2B-512 WHIRLPOOL GOST-STREEBOG-256 GOST-STREEBOG-512 SHAKE-128)
    end
  end
end
