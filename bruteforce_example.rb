#!/usr/bin/env ruby

require 'optparse'
require 'cobreak/cobreak'  # Cargar la extensión principal de CoBreak

class WPABruteforce
  def initialize(options)
    @hash_file = options[:hash_file]
    @wordlist = options[:wordlist]
    @verbose = options[:verbose]
  end

  def parse_hash_line(line)
    # Formato esperado: CB$WPA$VERSION$ESSID$MAC_AP$MAC_STA$NONCE_AP$NONCE_STA$EAPOL$KEYMIC
    parts = line.strip.split('$')
    return nil unless parts[0] == 'CB' && parts[1] == 'WPA'

    {
      essid: [parts[3]].pack('H*'),
      mac_ap: [parts[4]].pack('H*'),
      mac_sta: [parts[5]].pack('H*'),
      nonce_ap: [parts[6]].pack('H*'),
      nonce_sta: [parts[7]].pack('H*'),
      eapol: [parts[8]].pack('H*'),
      keymic: [parts[9]].pack('H*')
    }
  end

  def crack
    # Leer el hash
    hash_data = File.read(@hash_file).strip
    hash_info = parse_hash_line(hash_data)
    
    unless hash_info
      puts "Error: Invalid hash format"
      return false
    end

    puts "Target Network: #{hash_info[:essid]}"
    puts "BSSID: #{hash_info[:mac_ap].unpack('H*')[0]}"
    puts "Client: #{hash_info[:mac_sta].unpack('H*')[0]}"
    puts "Starting dictionary attack..."

    attempts = 0
    start_time = Time.now

    # Usar la extensión CoBreak::AttackWordlist para el crackeo
    File.foreach(@wordlist) do |line|
      password = line.strip
      attempts += 1
      
      if @verbose && attempts % 1000 == 0
        elapsed = Time.now - start_time
        speed = attempts / elapsed
        print "\rTried #{attempts} passwords... (#{speed.to_i} p/s)"
      end

      # Usar la función de crackeo de la extensión
      if CoBreak::AttackWordlist::WPA.crack(hash_info, password)
        elapsed = Time.now - start_time
        puts "\nPassword found: #{password}"
        puts "Time elapsed: #{elapsed.round(2)} seconds"
        puts "Attempts: #{attempts}"
        puts "Speed: #{(attempts / elapsed).to_i} passwords/second"
        return true
      end
    end

    elapsed = Time.now - start_time
    puts "\nPassword not found"
    puts "Time elapsed: #{elapsed.round(2)} seconds"
    puts "Attempts: #{attempts}"
    puts "Speed: #{(attempts / elapsed).to_i} passwords/second"
    false
  end
end

if __FILE__ == $0
  options = {
    verbose: false
  }

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [options]"
    
    opts.on("-f", "--hash-file FILE", "Hash file from hccap2cobreak") do |f|
      options[:hash_file] = f
    end
    
    opts.on("-w", "--wordlist FILE", "Wordlist file") do |w|
      options[:wordlist] = w
    end
    
    opts.on("-v", "--verbose", "Show verbose output") do
      options[:verbose] = true
    end
    
    opts.on("-h", "--help", "Show this help message") do
      puts opts
      exit
    end
  end

  begin
    parser.parse!

    unless options[:hash_file] && options[:wordlist]
      puts parser
      exit 1
    end

    unless File.exist?(options[:hash_file])
      puts "Error: Hash file not found: #{options[:hash_file]}"
      exit 1
    end

    unless File.exist?(options[:wordlist])
      puts "Error: Wordlist file not found: #{options[:wordlist]}"
      exit 1
    end

    cracker = WPABruteforce.new(options)
    success = cracker.crack

    exit(success ? 0 : 1)

  rescue OptionParser::InvalidOption, OptionParser::MissingArgument
    puts parser
    exit 1
  rescue => e
    puts "Error: #{e.message}"
    puts e.backtrace if options[:verbose]
    exit 1
  end
end
