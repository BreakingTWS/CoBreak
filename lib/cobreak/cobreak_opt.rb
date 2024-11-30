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
        @options.cipher = %w[Base16 Base32 Base64 Ascii85 Binary Cesar Vigenere]
        @options.force_cipher = %w[Cesar Vigenere]
        if (@options.cipher.include?(@options.enc.capitalize)) or (@options.cipher.include?(@options.dec.capitalize));
          if (File.exists?(@options.algo));
            IO.foreach(@options.algo){|line|
              line.chomp!
              if (@options.cipher.include?(@options.enc.capitalize))
                CoBreak::Cifrado.cipher(line.to_s)
              elsif (@options.cipher.include?(@options.dec.capitalize))
                CoBreak::Decifrado.cipher(line.to_s)
              else
                CoBreak::BruteCipher.crack(line.to_s)
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
        show.crypt = %w[MD4 MD5 HALF-MD5 SHA1 SHA2-224 SHA2-256 SHA2-384 SHA2-512 SHA3-224 SHA3-256 SHA3-384 SHA3-512 RIPEMD-160 TIGER-160 DOUBLE-SHA1 BLAKE2S-128 BLAKE2S-160 BLAKE2B-160 BLAKE2S-224 BLAKE2S-256 BLAKE2B-256 BLAKE2B-384 BLAKE2B-512 WHIRLPOOL STRIBOG-256 STRIBOG-512 SHAKE-128]
        if (show.crypt.include?(@options.typeforce.upcase)) or (show.crypt.include?(@options.typeforce.upcase));
          if (File.exists?(@options.algo));
            IO.foreach(@options.algo){|line|
              line.chomp!
              EnCrypt::show(@options.typeforce, line) if (show.crypt.include?(@options.typeforce.upcase))
              DeCrypt::show(@options.typeforce, line) if (show.crypt.include?(@options.typeforce.upcase))
            }
          else
            if (show.crypt.include?(@options.encrypt.upcase))
              EnCrypt::show(@options.encrypt, @options.algo)
            end
            if (show.crypt.include?(@options.decrypt.upcase))
              DeCrypt::show(@options.decrypt.upcase, @options.algo)
              #DeCrypt::show(@options.decrypt, @options.algo)
            end
          end
        else
          abort "\e[31m[\e[37m✘\e[31m]\e[37m Invalid Hash Format"
        end
      end
    end
  end
end
