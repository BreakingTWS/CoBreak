require 'cobreak/function_hash'
require 'cobreak/cobreak'
class Forze_brute
  attr_accessor :hash_input, :type_hash, :crypt, :min_chr, :max_chr, :charact, :word, :wordlist, :result, :out, :verbose, :crack
  def initialize(author = 'BreakerTW')
    @author = author
    @result = nil
    @crack = nil
    @crypt = nil
    @dict = nil
    @word = nil
  end
  def verify(dato, word = File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", 'lib', 'cobreak', 'hash', 'hash.db'))
    hash_db = Sequel.sqlite
    hash_db.create_table? :datahash do
      String :ori
      String :hash
    end
    begin
      IO.foreach(word) {|lin|
        lin = lin.chomp
        hash_db[:datahash] << {ori:lin, hash:dato}
      }
    rescue Errno::ENOENT
      return
    end
    ha = hash_db[:datahash].filter(ori:dato).map(:hash)
    arr = Array.new
    arr << dato
    if (ha == arr)
      puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Hash already existing in the database: #{dato}"
      puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m show the hash using --show, see the help parameter for more information\e[0m"
      exit
    end
  end
  def word(dato, wordlist, type, out, verbose = false)
    begin
      raise Errno::EACCES, "\e[1;31m[\e[1;37m✘\e[1;31m]\e[1;37m root privileges needed" if `whoami`.chomp != "root"
    rescue  Errno::EACCES => e
      puts e.message
      exit
    end

    forzebrute = OpenStruct.new
    @hash_input = dato
    @type_hash = type
    @out = out
    @verbose = verbose
    @wordlist = wordlist

    File.foreach(File.join(Gem.path[1], "gems","cobreak-#{CoBreak.version}" , "lib", "cobreak", "config", "database.db"), mode: 'r'){|booleano|
    forzebrute.booleano = booleano
    if (booleano.eql?('true'))
      verify(dato)
    end
    }

    if (type_hash.downcase.eql?('md4'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::MD5.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('md5'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::MD5.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('half-md5'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::HALF_MD5.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha1'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA1.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('double-sha1'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::DOUBLE_SHA1.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha2-224'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA2_224.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha2-256'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA2_256.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha2-384'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA2_384.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha2-512'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA2_512.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha3-224'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA3_224.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha3-256'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA3_256.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha3-384'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA3_384.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('sha3-512'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::SHA3_512.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('ripemd-160'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::RIPEMD_160.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('tiger-160'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::TIGER_160.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('blake2s-128'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::BLAKE2S_128.crack(hash_input, wordlist)
    elsif (type_hash.downcase.eql?('blake2s-160'))
      forzebrute.time = Time.now
      @result = CoBreak::AttackWordlist::BLAKE2S_160.crack(hash_input, wordlist)
    end

    if !(result.nil?)
      puts "\r\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Password Crack: #{result}"
      #puts "\r\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Number of lines: #{lin}"
      puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Hash Cracking in #{Time.now - forzebrute.time} seconds"
      if !(out.nil?)
        File.open(out, mode: 'a'){|out|
          out.puts "=================================================="
          out.puts "software: CoBreak #{CoBreak.version}"
          out.puts "Type Hash: #{type_hash}\n"
          out.puts "#{result.chomp}:#{crypt.hexdigest(result)}"
          out.puts "=================================================="
        }
      end
    else
      puts "\r\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Not Cracking Text: #{hash_input}"
      puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Time: #{Time.now - forzebrute.time} seconds\e[0m"
    end
    
    if (forzebrute.booleano.eql?('true'))
      $datBas::database(hash_input)
      DB::database(result, File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", 'lib', 'cobreak', 'show', "#{type_hash.upcase}.db"))
    end

      

=begin
        begin
          if (verbose)
            thread = Thread.new do
              dict = File.open(wordlist, mode: 'r')
              while word = dict.gets
                lin += 1
                $word = word
                if (crypt.hexdigest(word.chomp).eql?(hash_input))
                  @result = word
                  verbose = false
                  thread.kill
                end
              end
              verbose = 'no'
            end
          else
            dict = File.open(wordlist, mode: 'r')
            while word = dict.gets
              lin += 1
              begin
                if (crypt.hexdigest(word.chomp).eql?(hash_input.chomp))
                  @result = word
                  verbose = false
                  break
                end
              rescue
              end
            end
          end
          while (verbose == true)
            STDOUT.flush
            begin
              print "\r\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Password Crack: #{$word.chomp}" + " " *30
            rescue
            end
            sleep(0.1)
          end

          
          
        rescue Interrupt
        puts "\n\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Interrupt mode"
        puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Password Not Cracked"
        puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Number of Lines: #{lin}"
        puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Wait Time: #{Time.now - forzebrute.time} seconds\e[0m"
        exit
      end
=end
  end
  def chars(dato, range, char, type, out, verbose = false)
    begin
      raise Errno::EACCES, "\e[1;31m[\e[1;37m✘\e[1;31m]\e[1;37m root privileges needed" if `whoami`.chomp != "root"
    rescue  Errno::EACCES => e
      puts e.message
      exit
    end
    bool = File.open(File.join(Gem.path[1], "gems","cobreak-#{CoBreak.version}" , "lib", "cobreak", "config", "database.db"))
    bool = bool.readlines[0].to_s.chomp
    if (bool.eql?('true'))
      verify(dato)
    end
    forzechars = OpenStruct.new
    forzechars.dato = dato
    forzechars.range = range
    forzechars.char = char.chars
    forzechars.type = type
    forzechars.out = out
    forzechars.verbose = verbose
    forzechars.cont = Array.new
    forzechars.result = nil
    if (forzechars.type.downcase.eql?('md4'))
      forzechars.crypt = OpenSSL::Digest::MD4.new
    elsif (forzechars.type.downcase.eql?('md5'))
      forzechars.crypt = OpenSSL::Digest::MD5.new
    elsif (forzechars.type.downcase.eql?('sha1'))
      forzechars.crypt = OpenSSL::Digest::SHA1.new
    elsif (forzechars.type.downcase.eql?('sha224'))
      forzechars.crypt = OpenSSL::Digest::SHA224.new
    elsif (forzechars.type.downcase.eql?('sha256'))
      forzechars.crypt = OpenSSL::Digest::SHA256.new
    elsif (forzechars.type.downcase.eql?('sha384'))
      forzechars.crypt = OpenSSL::Digest::SHA384.new
    elsif (forzechars.type.downcase.eql?('sha512'))
      forzechars.crypt = OpenSSL::Digest::SHA512.new
    elsif (forzechars.type.downcase.eql?('ripemd160'))
      forzechars.crypt = OpenSSL::Digest::RIPEMD160.new
    end
    lin = 0
    begin
      forzechars.time = Time.now
      for range in (forzechars.range[0].to_i..forzechars.range[1].to_i).to_a
        for chars in forzechars.char.repeated_permutation(range).map(&:join)
          lin += 1
          if (forzechars.verbose.eql?(true))
            print "\r\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Password Crack: #{chars}"
          end
          if (forzechars.crypt.hexdigest(chars).eql?(forzechars.dato))
            forzechars.result = chars
            puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Password Crack: #{chars}"
            puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Number of Lines: #{lin}"
            puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Hash Cracking in #{Time.now - forzechars.time} seconds"
            if bool.eql?('true')
              forzechars.type = forzechars.type.downcase
              $datBas::database(forzechars.crypt.hexdigest(chars))
              DB::database(chars, File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", 'lib', 'cobreak', 'show', "#{forzechars.type}.db"))
            end
            if !(forzechars.out.nil?)
              File.open(forzechars.out, mode: 'a'){|out|
                out.puts "=================================================="
                out.puts "software: CoBreak #{CoBreak.version}"
                out.puts "Type Hash: #{forzechars.type}\n"
                out.puts "#{chars}:#{forzechars.crypt.hexdigest(chars)}"
                out.puts "=================================================="
              }
            end
            return 0
          end
        end
      end
    rescue Interrupt
      puts "\n\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Interrupt mode"
      puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Password Not Cracked"
      puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Number of Lines: #{lin}"
      puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Wait Time: #{Time.now - forzechars.time} seconds\e[0m"
      exit
    end
    if (forzechars.result.nil?)
      puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Not Cracking Text: #{forzechars.dato}"
      puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Time: #{Time.now - forzechars.time}\e[0m"
      exit
    end
  end
end
ForzeBrute = Forze_brute.new