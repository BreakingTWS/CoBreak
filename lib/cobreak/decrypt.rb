require 'cobreak/version'
require 'cobreak/cobreak'
class Decrypt
  def show(mode, dato)
    decrypt = OpenStruct.new
    decrypt.mode = mode
    decrypt.wordlist = File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", 'lib', 'cobreak', 'show', "#{decrypt.mode}.db")
    #decrypt.wordlist = File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", 'lib', 'cobreak', 'show', "MD5.db")
    dbs = Sequel.sqlite
    dbs = Sequel.sqlite
    dbs.create_table? :hashes do
      String :original
      String :hash
    end
    File.foreach(decrypt.wordlist) {|line|
      line.chomp!
      if(decrypt.mode.downcase=='md4')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::MD4.hexdigest(line)}
      elsif(decrypt.mode.downcase=='md5')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::MD5.hexdigest(line)}
      elsif(decrypt.mode.downcase=='half-md5')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::HALF_MD5.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha1')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA1.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha2-224')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA2_224.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha2-256')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA2_256.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha2-384')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA2_384.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha2-512')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA2_512.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha3-224')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA3_224.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha3-256')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA3_256.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha3-384')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA3_384.hexdigest(line)}
      elsif(decrypt.mode.downcase=='sha3-512')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::SHA3_512.hexdigest(line)}
      elsif(decrypt.mode.downcase=='ripemd-160')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::RIPEMD_160.hexdigest(line)}
      elsif(decrypt.mode.downcase=='tiger-160')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::TIGER_160.hexdigest(line)}
      elsif(decrypt.mode.downcase=='double-sha1')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::DOUBLE_SHA1.hexdigest(line)}
      elsif(decrypt.mode.downcase=='blake2s-128')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::BLAKE2S_128.hexdigest(line)}
      elsif(decrypt.mode.downcase=='blake2s-160')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::BLAKE2S_160.hexdigest(line)}
      elsif(decrypt.mode.downcase=='blake2s-224')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::BLAKE2S_224.hexdigest(line)}
      elsif(decrypt.mode.downcase=='blake2s-256')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::BLAKE2S_256.hexdigest(line)}
      elsif(decrypt.mode.downcase=='blake2b-160')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::BLAKE2B_160.hexdigest(line)}
      elsif(decrypt.mode.downcase=='blake2b-256')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::BLAKE2B_256.hexdigest(line)}
      elsif(decrypt.mode.downcase=='blake2b-384')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::BLAKE2B_384.hexdigest(line)}
      elsif(decrypt.mode.downcase=='blake2b-512')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::BLAKE2B_512.hexdigest(line)}
      elsif(decrypt.mode.downcase=='whirlpool')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::WHIRLPOOL.hexdigest(line)}
      elsif(decrypt.mode.downcase=='gost-streebog-256')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::GOST_STREEBOG_256.hexdigest(line)}
      elsif(decrypt.mode.downcase=='gost-streebog-512')
        dbs[:hashes] << {original:line, hash:CoBreak::GCrypt::GOST_STREEBOG_512.hexdigest(line)}
      end
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
