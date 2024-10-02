require 'openssl'
require 'cobreak/function_db' 
require 'cobreak/function_hash'
require 'cobreak/cobreak'
require 'cobreak/version'
class Encrypt
  def show(mode, dato)
    bool = File.open(File.join(Gem.path[1], "gems","cobreak-#{CoBreak.version}" , "lib", "cobreak", "config", "database.db"))
    bool = bool.readlines[0].to_s.chomp
    encrypt = OpenStruct.new
    encrypt.mode = mode.downcase
    encrypt.dato = dato
    case encrypt.mode
      when ('md4')
        encrypt.crypt = CoBreak::OpenSSL::MD4.hexdigest(dato)
      when ('md5')
        encrypt.crypt = CoBreak::OpenSSL::MD5.hexdigest(dato)
      when ('sha1')
        encrypt.crypt = CoBreak::OpenSSL::SHA1.hexdigest(dato)
      when ('sha224')
        encrypt.crypt = CoBreak::OpenSSL::SHA224.hexdigest(dato)
      when ('sha256')
        encrypt.crypt = CoBreak::OpenSSL::SHA256.hexdigest(dato)
      when ('sha384')
        encrypt.crypt = CoBreak::OpenSSL::SHA384.hexdigest(dato)
      when ('sha512')
        encrypt.crypt = CoBreak::OpenSSL::SHA512.hexdigest(dato)
      when ('ripemd160')
        encrypt.crypt = CoBreak::OpenSSL::RIPEMD160.hexdigest(dato)
      else "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Type Hash Not Found"
    end
    unless (encrypt.crypt.nil?)
      puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Encrypted Text: #{encrypt.crypt}"
      begin
        if bool.eql?('true')
          $datBas::database(encrypt.crypt)
          DB::database(dato, File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", 'lib', 'cobreak', 'show', "#{encrypt.mode}.db"))
          puts "\n\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Hash Saved In The Database"
        end
      rescue Errno::EACCES
        puts "\n\n\e[1;31m[\e[1;37m✘\e[1;31m]\e[1;37m Access Denied"
        puts "\e[1;31m[\e[1;37m✘\e[1;31m]\e[1;37m You need root privileges to save the hash to the database"
      end
    else
      puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Not Encrypt Text..."
    end
  end
end
EnCrypt = Encrypt.new
