module CoBreak
  class List
    #all list formats and types
    def initialize(options)
      all = Array.new
      all << "Base64" << "Base32" << "Base16" << "Ascii85" << "Binary" << "Cesar" << "Vigenere"
      if (options.list.eql?("cipher"))
        list_cipher = all.map do |type|
          {category: 'Cipher', name: type}
        end
        puts "\n"
        puts " " * 2 + "#{'ID' + ' ' * 3} | #{' ' + 'Name' + ' ' * 27} | #{'Category' + ' ' * 6}"
        puts "=" * 8 + "+" + "=" * 34 + "+" + "=" * 20
        salt = " "
        list_cipher.each_with_index do |cipher, index|
          puts " " * 2 + "#{index + 1}" + " " * 4 + salt + "|" + " " * 2 + "#{cipher[:name].ljust(31)} | #{cipher[:category].ljust(8)}"
          if(index==8)
            salt = ""
          end
        end
      end
      all.clear
      all << "MD4" << "MD5" << "HALF-MD5" << "SHA1" << "DOUBLE-SHA1" << "SHA2-224" << "SHA2-256" << "SHA2-384" << "SHA2-512" << "SHA3-224" << "SHA3-256" << "SHA3-384" << "SHA3-512" << "RIPEMD-160" << "TIGER-160" << "BLAKE2S-128" << "BLAKE2S-160" << "BlAKE2B-160" << "BLAKE2S-224" << "BLAKE2S-256" << "BLAKE2B-256" << "BLAKE2B_384" << "BLAKE2B-512" << "WHIRLPOOL" << "GOST_STREEBOG_256" << "GOST_STREEBOG_256" << "SHAKE-128"
      if (options.list.eql?("digest"))
        list_algorithms = all.map do |type|
          {category: 'Raw-Hash', name: type}
        end
        puts "\n"
        puts " " * 2 + "#{'ID' + ' ' * 3} | #{' ' + 'Name' + ' ' * 27} | #{'Category' + ' ' * 6}"
        puts "=" * 8 + "+" + "=" * 34 + "+" + "=" * 20
        salt = " "
        list_algorithms.each_with_index do |hash, index|
          puts " " * 2 + "#{index + 1}" + " " * 4 + salt + "|" + " " * 2 + "#{hash[:name].ljust(31)} | #{hash[:category].ljust(8)}"
          if(index==8)
            salt = ""
          end
        end
      end
    end
  end
end
