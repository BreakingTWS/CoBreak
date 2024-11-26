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
        out_db = 'MD4'
      when ('md5')
        encrypt.crypt = CoBreak::OpenSSL::MD5.hexdigest(dato)
        out_db = 'MD5'
      when ('half-md5')
        encrypt.crypt = CoBreak::OpenSSL::HALF_MD5.hexdigest(dato)
        out_db = 'HALF-MD5'
      when ('sha1')
        encrypt.crypt = CoBreak::OpenSSL::SHA1.hexdigest(dato)
        out_db = 'SHA1'
      when ('sha2-224')
        encrypt.crypt = CoBreak::OpenSSL::SHA2_224.hexdigest(dato)
        out_db = 'SHA2-224'
      when ('sha2-256')
        encrypt.crypt = CoBreak::OpenSSL::SHA2_256.hexdigest(dato)
        out_db = 'SHA2-256'
      when ('sha2-384')
        encrypt.crypt = CoBreak::OpenSSL::SHA2_384.hexdigest(dato)
        out_db = 'SHA2-384'
      when ('sha2-512')
        encrypt.crypt = CoBreak::OpenSSL::SHA2_512.hexdigest(dato)
        out_db = 'SHA2-512'
      when ('sha3-224')
        encrypt.crypt = CoBreak::OpenSSL::SHA3_224.hexdigest(dato)
        out_db = 'SHA3-224'
      when ('sha3-256')
        encrypt.crypt = CoBreak::OpenSSL::SHA3_256.hexdigest(dato)
        out_db = 'SHA3-256'
      when ('sha3-384')
        encrypt.crypt = CoBreak::OpenSSL::SHA3_384.hexdigest(dato)
        out_db = 'SHA3-384'
      when ('sha3-512')
        encrypt.crypt = CoBreak::OpenSSL::SHA3_512.hexdigest(dato)
        out_db = 'SHA3-512'
      when ('ripemd-160')
        encrypt.crypt = CoBreak::OpenSSL::RIPEMD_160.hexdigest(dato)
        out_db = 'RIPEMD-160'
      when ('SHAKE-128')
        encrypt.crypt = CoBreak::GCrypt::SHAKE_128.hexdigest(dato)
        out_db = 'SHAKE-128'
      when ('gost-streebog-256')
        encrypt.crypt = CoBreak::GCrypt::GOST_STREEBOG_256.hexdigest(dato)
        out_db = 'GOST-STREEBOG-256'
      when ('gost-streebog-512')
        encrypt.crypt = CoBreak::GCrypt::GOST_STREEBOG_512.hexdigest(dato)
        out_db = 'GOST-STREEBOG-512'
      when ('tiger-160')
        encrypt.crypt = CoBreak::GCrypt::TIGER_160.hexdigest(dato)
        out_db = 'TIGER-160'
      when ('double-sha1')
        encrypt.crypt = CoBreak::GCrypt::DOUBLE_SHA1.hexdigest(dato)
        out_db = 'DOUBLE-SHA1'
      when ('blake2s-128')
        encrypt.crypt = CoBreak::GCrypt::BLAKE2S_128.hexdigest(dato)
        out_db = 'BLAKE2S-128'
      when ('blake2s-160')
        encrypt.crypt = CoBreak::GCrypt::BLAKE2S_160.hexdigest(dato)
        out_db = 'BLAKE2S-160'
      when ('blake2b-160')
        encrypt.crypt = CoBreak::GCrypt::BLAKE2B_160.hexdigest(dato)
        out_db = 'BLAKE2B-160'
      when ('blake2s-224')
        encrypt.crypt = CoBreak::GCrypt::BLAKE2S_224.hexdigest(dato)
        out_db = 'BLAKE2S-224'
      when ('blake2s-256')
        encrypt.crypt = CoBreak::GCrypt::BLAKE2S_256.hexdigest(dato)
        out_db = 'BLAKE2S-256'
      when ('blake2b-256')
        encrypt.crypt = CoBreak::GCrypt::BLAKE2B_256.hexdigest(dato)
        out_db = 'BLAKE2B-256'
      when ('blake2b-384')
        encrypt.crypt = CoBreak::GCrypt::BLAKE2B_384.hexdigest(dato)
        out_db = 'BLAKE2B-384'
      when ('blake2b-512')
        encrypt.crypt = CoBreak::GCrypt::BLAKE2B_512.hexdigest(dato)
        out_db = 'BLAKE2B-512'
      when ('whirlpool')
        encrypt.crypt = CoBreak::GCrypt::WHIRLPOOL.hexdigest(dato)
        out_db = 'WHIRLPOOL'
      else "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Type Hash Not Found"
    end
    unless (encrypt.crypt.nil?)
      puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Encrypted Text: #{encrypt.crypt}"
      puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Bits: #{encrypt.crypt.length}"
      puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Bytes: #{encrypt.crypt.length/2}"
      begin
        if bool.eql?('true')
          $datBas::database(encrypt.crypt)
          DB::database(dato, File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", 'lib', 'cobreak', 'show', "#{out_db}.db"))
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
