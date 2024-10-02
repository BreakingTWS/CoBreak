#!/bin/env ruby
module CoBreak
  class Box
    def self.var(options)
      @options = options
      $options = options
    end
    begin
      require 'cobreak/cifrado'
      require 'cobreak/decifrado'
      require 'cobreak/encrypt'
      require 'cobreak/decrypt'
    rescue LoadError => e
      puts e.message
      puts "A file is missing from the repository"
      puts ""
      exit(1)
    end
    #encoding and decoding algoritmhs
    class Cipher
      def self.coding()
        @options = $options
        @options.enc = "" if @options.enc.nil? == true
        @options.dec = "" if @options.dec.nil? == true
        @options.cipher = %w[Base16 Base32 Base64 Ascii85 Binary Cesar]
        if (@options.cipher.include?(@options.enc.capitalize)) or (@options.cipher.include?(@options.dec.capitalize));
          if (File.exists?(@options.algo));
            IO.foreach(@options.algo){|line|
              line.chomp!
              if (@options.cipher?(@options.enc.capitalize))
                CoBreak::Cifrado.cipher(line.to_s)
              end
              if (@options.cipher.include?(@options.dec.capitalize))
                CoBreak::Decifrado.cipher(line.to_s)
              end
            }
          else
            if (@options.cipher.include?(@options.enc.capitalize))
              CoBreak::Cifrado::cipher(@options.enc, @options.algo.to_s)
            end
            if (@options.cipher.include?(@options.dec.capitalize))
              CoBreak::Decifrado::cipher(@options.dec,@options.algo.to_s)
            end
          end
        end
      end
    end
    class Cryptgraphy
      def self.crypt()
        @options = $options
        @options.encrypt = "" if @options.encrypt.nil? == true
        @options.decrypt = "" if @options.decrypt.nil? == true
        show = OpenStruct.new
        show.crypt = %w[MD4 MD5 SHA1 SHA224 SHA256 SHA384 SHA512 RIPEMD160]
        if (show.crypt.include?(@options.encrypt.upcase)) or (show.crypt.include?(@options.decrypt.upcase));
          if (File.exists?(@options.algo));
            IO.foreach(@options.algo){|line|
              line.chomp!
              EnCrypt::show(@options.encrypt, line) if (show.crypt.include?(@options.encrypt.upcase))
              DeCrypt::show(@options.decrypt, line) if (show.crypt.include?(@options.decrypt.upcase))
            }
          else
            if (show.crypt.include?(@options.encrypt.upcase))
              EnCrypt::show(@options.encrypt, @options.algo)
            end
            if (show.crypt.include?(@options.decrypt.upcase))
              DeCrypt::show(@options.decrypt, @options.algo)
            end
          end
        else
          abort "\e[31m[\e[37m✘\e[31m]\e[37m Invalid Hash Format"
        end
      end
    end
  end
end
