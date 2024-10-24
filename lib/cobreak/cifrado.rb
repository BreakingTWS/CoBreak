require 'ascii85'

module CoBreak
  class Cifrado
    def self.cipher(mode, dato)
      cipher = OpenStruct.new
      cipher.mode = mode
      cipher.dato = dato
      if (cipher.mode.eql?('base16'))
        cipher.result = CoBreak::Cipher::Base16.encode(dato)
      elsif (cipher.mode.eql?('base32'))
        cipher.result = CoBreak::Cipher::Base32.encode(dato)
      elsif (cipher.mode.eql?('base64'))
        cipher.result = CoBreak::Cipher::Base64.encode(dato)
      elsif (cipher.mode.eql?('ascii85'))
        cipher.result = Ascii85.encode(dato)
      elsif (cipher.mode.eql?('cesar'))
        cipher.result = CoBreak::Cipher::Cesar.encode(dato, ARGV[0].to_i)
      elsif (cipher.mode.eql?('binary'))
        cipher.result = CoBreak::Cipher::Binary.encode(dato)
      end
      unless (cipher.result.nil?) or (cipher.result.eql?(cipher.dato))
        puts "\n\e[1;32m[\e[37m+\e[1;32m]\e[37m Ciphertext: #{cipher.result}"
        puts "\e[1;32m[\e[37m+\e[1;32m]\e[37m Number Rotations: #{ARGV[0]}" if (cipher.mode.eql?('cesar'))
      else
        puts "\e[1;31m[\e[37m+\e[1;31m]\e[37m Not Cipher Text..."
      end
    end
  end
end
