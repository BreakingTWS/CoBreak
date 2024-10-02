require 'cobreak/cobreak'
require 'base32'
require 'base16'
require 'ascii85'
require 'cobreak/cesar'
require 'cobreak/binary'
module CoBreak
  class Cifrado
    def self.cipher(mode, dato)
      cipher = OpenStruct.new
      cipher.mode = mode
      cipher.dato = dato
      if (cipher.mode.eql?('base16'))
        cipher.result = Base16.encode16(dato)
      elsif (cipher.mode.eql?('base32'))
        cipher.result = Base32.encode(dato)
      elsif (cipher.mode.eql?('base64'))
        cipher.result = CoBreak::Base64.encode(dato)
      elsif (cipher.mode.eql?('ascii85'))
        cipher.result = Ascii85.encode(dato)
      elsif (cipher.mode.eql?('cesar'))
        cipher.result = Cesar.cesar(dato, ARGV[0].to_i)
      elsif (cipher.mode.eql?('binary'))
        cipher.result = CoBreak::Binary.binary(dato)
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
