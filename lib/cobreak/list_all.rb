module CoBreak
  class List
    #all list formats and types
    def initialize(options)
      all = Array.new
      all << "Base64" << "Base32" << "Base16" << "Ascii85" << "Binary" << "Cesar"
      if (options.list.eql?("TYPE"))
        puts "\nMode Cipher:"
        puts all
      end
      all.clear
      all << "MD4" << "MD5" << "SHA1" << "SHA224" << "SHA256" << "SHA384" << "SHA512" << "RIPEMD160"
      if (options.list.eql?("FORMAT"))
        puts "\nMode Cryptography:"
        puts all
      end
    end
  end
end
