module CoBreak
  class Details
    def self.info()
      return "The CoBreak script is an cipher and cryptography tool made with the purpose of facilitating the encryption of data or others, it includes parameters to brute force the hashes through dictionaries"
    end
    def self.dependecias()
      return %w(base14 base32 base16 ascii85 cesar binary openssl animat sequel sqlite3)
    end
    def self.date()
      return "2020-5-25"
    end
    def self.cipher()
      return %w(base64 base32 base16 ascii85 cesar binary)
    end
    def self.crypt()
      return %w(MD4 MD5 SHA1 SHA224 SHA256 SHA384 SHA512 RIPEMD160)
    end
  end
end
