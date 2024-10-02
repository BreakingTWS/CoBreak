require 'cobreak/version'
class Decrypt
  def show(mode, dato)
    decrypt = OpenStruct.new
    decrypt.mode = mode.downcase
    decrypt.wordlist = File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", 'lib', 'cobreak', 'show', "#{decrypt.mode}.db")
    dbs = Sequel.sqlite
    dbs.create_table? :hashes do
      String :original
      String :hash
    end
      case decrypt.mode
        when ('md4')
          decrypt.crypt = OpenSSL::Digest::MD4.new
        when ('md5')
          decrypt.crypt = OpenSSL::Digest::MD5.new
        when ('sha1')
          decrypt.crypt = OpenSSL::Digest::SHA1.new
        when ('sha224')
          decrypt.crypt = OpenSSL::Digest::SHA224.new
        when ('sha256')
          decrypt.crypt = OpenSSL::Digest::SHA256.new
        when ('sha384')
          decrypt.crypt = OpenSSL::Digest::SHA384.new
        when ('sha512')
          decrypt.crypt = OpenSSL::Digest::SHA512.new
        when ('ripemd160')
          decrypt.crypt = OpenSSL::Digest::RIPEMD160.new
      end
    File.foreach(decrypt.wordlist) {|line|
      line.chomp!
      dbs[:hashes] << {original:line, hash:decrypt.crypt.hexdigest(line)}
    }
   decrypt.pass = dbs[:hashes].filter(hash:dato).map(:original)
   unless (decrypt.pass.empty?)
     puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Type Hash: #{decrypt.mode}"
     puts "\e[1;32m[\e[1;37m+\e[1;32m]\e[1;37m Hash Found: #{decrypt.pass.join(',')}\e[0m"
   else
     puts "\e[1;31m[\e[1;37m+\e[1;31m]\e[1;37m Hash Not Found in Database...\e[0m"
   end
  end
end
DeCrypt = Decrypt.new
