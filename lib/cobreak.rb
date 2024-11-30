begin
  require 'cobreak/cobreak'  # Load C extension
  
  # Debug output to verify modules are loaded
  puts "Checking loaded modules:"
  puts "CoBreak defined: #{defined?(CoBreak)}"
  puts "CoBreak::GCrypt defined: #{defined?(CoBreak::GCrypt)}"
  puts "CoBreak::Cipher defined: #{defined?(CoBreak::Cipher)}"
  if defined?(CoBreak::GCrypt)
    puts "Available GCrypt classes:"
    puts "MD4: #{defined?(CoBreak::GCrypt::MD4)}"
    puts "MD5: #{defined?(CoBreak::GCrypt::MD5)}"
    puts "TIGER_160: #{defined?(CoBreak::GCrypt::TIGER_160)}"
    puts "BLAKE2B_512: #{defined?(CoBreak::GCrypt::BLAKE2B_512)}"
  end
rescue LoadError => e
  puts "Error loading C extension: #{e.message}"
  puts "Please ensure the extension is properly built"
  exit 1
end

require 'cobreak/version'
require 'fileutils'
require 'cobreak/info_author'
require 'cobreak/details'

# Load core functionality
require 'cobreak/cifrado'
require 'cobreak/decifrado'
require 'cobreak/force'
require 'cobreak/force_brute'
require 'cobreak/force_chars'
require 'cobreak/force_cipher'

# GUI components
module CoBreak
  autoload :GUI, 'cobreak/gui'
end
