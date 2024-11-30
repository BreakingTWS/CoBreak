require 'cobreak/cobreak_opt'
require 'cobreak/force_brute'
require 'cobreak/force_chars'
require 'cobreak/version'
require 'cobreak/list_all'
require 'sequel'
require 'openssl'
module CoBreak
  class ParseOPT
    def self.optparse(options)
      begin
      OptionParser.new do|param|
        param.banner = "Usage: cobreak [--mode] [--options] [--input text or file]"
        param.separator ''
        param.separator "Mode Cipher:"
        param.on('-e', '--encoding', String, 'encoding input text or file'){options.enc = en_co = true}
        param.on('-d', '--decoding', String, 'decoding input text or file'){options.dec = true}
        param.separator "Mode Cryptography"
        param.on('--encrypt', String, 'encrypt parameter'){options.encrypt = true}
        param.separator "Mode BruteForce"
        param.on('-b', '--bruteforce=MODE', String, 'Select mode for brute force'){|modeforce|options.bruteforce = modeforce}
        param.separator "Select Mode Brute Force"
        param.on('-t', '--type=TYPE', String, 'Select type for Brute Force'){|typeforce|options.typeforce = typeforce}
        param.separator ""
        param.separator "Options:"
        param.on('-l', '--list=TYPE', String, 'list modes bruteforce or cipher types of hash formats'){|lin| options.list = lin}
        param.on('-r', '--range MIN MAX', Array, "word chars length"){|rang| options.range = rang}
        param.on('-c', '--chars CHARACTERS', String, 'character input to generate word lists'){|chars| options.chars = chars}
        param.on('-w', '--wordlist=WORDLIST', 'Wordlist mode, read words from FILE or stadin (default: rockyou)'){|wordlist| options.wordlist = wordlist}
        param.on('--show=[FORMAT]', String, 'show decrypted specific hash'){|de_en| options.decrypt = de_en}
        param.on('-i', '--input FILE or TEXT', String, 'take file or text to carry out the process'){|alg| options.algo = alg}
        param.on('-o', '--output FiLe', String, 'output the software'){|out| options.out = out}
        param.on('-v', '--verbose', 'verbose mode'){options.verbose = true}
        param.on('--usage', 'show examples of use of this tool')do
          puts "usage: cobreak [--mode] [--options] [--input] text or file"
          puts ""
          puts "cipher:"
          puts ""
          puts "cobreak --encoding --type [cipher type] --input [text]"
          puts "cobreak --decoding --type [cipher type] --input [text]"
          puts ""
          puts "note that the cesar cipher mode has to have a number in front to know the rotations"
          puts "examples: --encoding --type cesar 5 --input [text]"
          puts ""
          puts "bruteforce:"
          puts ""
          puts "cobreak --bruteforce [mode] --type [type] --wordlist [wordlist] --input pass|passfile"
          puts "cobreak --bruteforce [mode] --type [type] --chars [characters] --range MIN MAX --input pass|passfile"
          puts ""
          puts ""
          puts "Los modos de fuerza bruta para cobreak son [cipher] and [digest]"
          puts "Para ver los tipos de algortimos usables en el programa ejecuta:"
          puts "cobreak --list [cypher]"
          puts "cobreak --list [digest]"
        end
        param.on_tail('-h', '--help', 'command to view help parameters'){puts param; exit}
        param.on_tail('-V', '--version', 'show version'){puts "CoBreak version #{CoBreak.version}"; exit}
        param.separator ''
      end.parse!
      rescue OptionParser::MissingArgument => missing
        if missing.to_s.include?("--wordlist")
          options.wordlist = File.join(Gem.path[1], 'gems', "cobreak-#{CoBreak.version}", 'diccionario.txt')
        elsif missing.to_s.include?("--chars")
          options.chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        elsif missing.to_s.include?("--list")
          puts missing
          puts "cobreak --list type"
          exit 1
        else
          puts missing.message
        end
      ensure
        if (options.wordlist == "rockyou")
          unless (File.exists?(options.wordlist))
            #options.wordlist = File.join(Gem.path[1], 'gems', "cobreak-#{CoBreak.version}", 'diccionario.txt')
            options.wordlist = File.join('/usr', 'share', 'wordlists', 'rockyou.txt')
          end
        end
      end

      CoBreak::Box.var(options)
      case options.bruteforce
        when ('0')
          options.bruteforce = 'md2'
        when ('1')
          options.bruteforce = 'md4'
        when ('2')
          options.bruteforce = 'md5'
        when ('3')
          options.bruteforce = 'half-md5'
        when ('4')
          options.bruteforce = 'sha1'
        when ('5')
          options.bruteforce = 'double-sha1'
        when ('6')
          options.bruteforce = 'sha2-224'
        when ('7')
          options.bruteforce = 'sha2-256'
        when ('8')
          options.bruteforce = 'sha2-384'
        when ('9')
          options.bruteforce = 'sha2-512'
        when ('10')
          options.bruteforce = 'sha3-224'
        when ('11')
          options.bruteforce = 'sha3-256'
        when ('12')
          options.bruteforce = 'sha3-384'
        when ('13')
          options.bruteforce = 'sha3-512'
        when ('14')
          options.bruteforce = 'ripemd-160'
        when ('15')
          options.bruteforce = 'tiger-160'
        when ('16')
          options.bruteforce = 'blake2s-128'
        when ('17')
          options.bruteforce = 'blake2s-160'
        when ('18')
          options.bruteforce = 'blake2b-160'
        when ('19')
          options.bruteforce = 'blake2s-224'
        when ('20')
          options.bruteforce = 'blake2s-256'
        when ('21')
          options.bruteforce = 'blake2b-256'
        when ('22')
          options.bruteforce = 'blake2b-384'
        when ('23')
          options.bruteforce = 'blake2b-512'
        when ('24')
          options.bruteforce = 'whirlpool'
        when ('25')
          options.bruteforce = 'stribog-256'
        when ('26')
          options.bruteforce = 'stribog-512'
        when ('27')
          options.bruteforce = 'shake-128'
        else
          puts ""
      end
      unless (options.list.nil?) or (options.list.empty?)
        unless (options.list.eql?("digest")) or (options.list.eql?("cipher"))
          puts "Fatal error, type for cobreak (digest) or (cipher)"
          exit 1 
        end
      end
      case options.typeforce
      when ('1')
        options.typeforce = 'Cesar'
      when ('2')
        options.typeforce = 'Vigenere'
      end

      if (options.encrypt.eql?(true))
        unless (options.enc.nil?) or (options.dec.nil?)
          CoBreak::Box::Cipher.coding()
        end
        unless (options.encrypt.nil?) or (options.decrypt.nil?)
          CoBreak::Box::Cryptgraphy.crypt()
        end
      end
      CoBreak::List.new(options)
      if (options.bruteforce=="digest")
        unless (options.wordlist.nil?) or (options.wordlist.empty?)
          bruteforce = CoBreak::BruteForze.new(options)
          bruteforce.banner_wordlist()
          bruteforce.wordlist
        end
        unless (options.chars.nil?) or (options.chars.empty?)
          options.range << ARGV[0].to_i
          brutechars = CoBreak::BruteChars.new(options)
          brutechars.banner_chars()
          brutechars.chars()
        end
      elsif (options.bruteforce=="cipher")
        unless (options.wordlist.nil?) or (options.wordlist.empty?)
          bruteforce = CoBreak::BruteCipher.new(options)
          bruteforce.banner_cipher()
          bruteforce.wordlist
        end
        unless (options.chars.nil?) or (options.chars.empty?)
          options.range << ARGV[0].to_i
          brutechars = CoBreak::BruteChars.new(options)
          brutechars.banner_chars()
          brutechars.chars()
        end
      end
    end
  end
end
