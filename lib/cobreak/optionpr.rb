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
        param.on('-enc', '--encoding=CIPHER', String, 'encoding input text or file'){|en_co| options.enc = en_co}
        param.on('-dec', '--decoding=CIPHER', String, 'decoding input text or file'){|de_co| options.dec = de_co}
        param.separator "Mode Cryptography"
        param.on('--encrypt=[FORMAT]', String, 'encrypt parameter'){|en_en| options.encrypt = en_en}
        param.separator "Mode BruteForce"
        param.on('-bword', '--brutewordlist=DIGEST', String, 'brute force mode to crack a hash whitch wordlist format'){|modeforce|options.bruteforce = modeforce}
        param.on('-bchar', '--brutechar=DIGEST', String, 'brute force mode to crack a hash whitch char generator format'){|modeforce|options.bruteforce = modeforce}
        param.on('-bcipherw', '--brutecipher=CIPHER', String, 'brute force mode to crack a hash cipher wordlist format'){|modeforce|options.bruteforce = modeforce}
        param.on('-bcipherw', '--brutecipherchar=CIPHER', String, 'brute force mode to crack a cipher whitch char generator'){|modeforce|options.bruteforce = modeforce}
        param.separator ""
        param.separator "Options:"
        param.on('-l', '--list=encoding or encrypt', String, 'list cipher types of hash formats'){|lin| options.list = lin}
        param.on('-r', '--range MIN MAX', Array, "word chars length"){|rang| options.range = rang}
        param.on('-c', '--chars CHARACTERS', String, 'character input to generate word lists'){|chars| options.chars = chars}
        param.on('-w', '--wordlist=WORDLIST', 'Wordlist mode, read words from FILE or stadin (default: rockyou)'){|wordlist| options.wordlist = wordlist}
        param.on('--show=[FORMAT]', String, 'show decrypted specific hash'){|de_en| options.decrypt = de_en}
        param.on('-i', '--input FILE or TEXT', String, 'take file or text to carry out the process'){|alg| options.algo = alg}
        param.on('-o', '--output FILe', String, 'output the software'){|out| options.out = out}
        param.on('-v', '--verbose', 'verbose mode'){options.verbose = true}
        param.on('--usage', 'show examples of use of this tool')do
          puts "usage: cobreak [--mode] [--options] [--input] text or file"
          puts ""
          puts "cipher:"
          puts ""
          puts "cobreak --encoding=[CIPHER] --input text or file"
          puts "cobreak --decoding=[CIPHER] --input text or file"
          puts ""
          puts "note that the cesar cipher mode has to have a number in front to know the rotations"
          puts "examples: --encoding=cesar 5 --input hola"
          puts ""
          puts "bruteforce:"
          puts ""
          puts "cobreak --bruteforce=[ENCRYPT] --wordlist=[WORDLIST] --input text or file"
          puts "cobreak --bruteforce=[ENCRYPT] --chars [CHARACTERS] --range MIN MAX --input text or file"
          puts ""
        end
        param.on_tail('-V', '--version', 'show version'){puts "CoBreak version #{CoBreak.version}"; exit}
        param.on_tail('-h', '--help', 'command to view help parameters'){puts param; exit}
        param.separator ''
      end.parse!
      rescue OptionParser::MissingArgument => missing
        if missing.to_s.include?("--wordlist")
          options.wordlist = File.join(Gem.path[1], 'gems', "cobreak-#{CoBreak.version}", 'diccionario.txt')
        elsif missing.to_s.include?("--chars")
          options.chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
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
      if !(options.enc.nil?) or !(options.dec.nil?)
        CoBreak::Box::Cipher.coding()
      end
      if !(options.encrypt.nil?) or !(options.decrypt.nil?)
        CoBreak::Box::Cryptgraphy.crypt()
      end
      CoBreak::List.new(options)
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
    end
  end
end
