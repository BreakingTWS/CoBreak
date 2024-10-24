#!/bin/env ruby
require 'ruby_figlet'
require 'cobreak/version'
using RubyFiglet
module CoBreak
  class BruteForze
    def initialize(options)
      @options = options
      @hash = %w[MD4 MD5 SHA1 SHA224 SHA256 SHA384 SHA512 RIPEMD160]
    end
    begin
      require 'cobreak/force'
    rescue LoadError => e
      puts e.message
      abort "reinstall gem new"
    end
    def banner_wordlist()
      puts "\e[0;31m"
      puts "cobreak".art("Bloody")
      puts "\e[0m"
      puts "\e[1;32m╭─[\e[37m CoBreak: #{CoBreak.version}"
      if (File.exists?(@options.wordlist.to_s))
        puts "\e[1;32m├─[\e[37m Wordlist: #{File.expand_path(@options.wordlist)}"
      else
        puts "\e[1;31m├─[\e[37m WordList Not Found"
      end
      if (@hash.include?(@options.bruteforce.to_s.upcase))
        puts "\e[1;32m├─[\e[37m Type Hash: #{@options.bruteforce.upcase}"
      else
        puts "\e[1;31m├─[\e[37m Type Hash Not Found"
      end
      unless (@options.algo.nil?) or (@options.algo.empty?)
        puts "\e[1;32m╰─[\e[37m Hash: #{@options.algo}\n\n"
      else
        puts "\e[1;31m╰─[\e[37m Hash Not Found"
      end
    end
    def wordlist()
      if (@options.wordlist.nil?) or (@options.wordlist.empty?) or ('-'.include?(@options.wordlist.to_s))
        abort "\n"
      end
      if (@hash.include?(@options.bruteforce.to_s.upcase))
        if (File.exists?(@options.algo.to_s))
          begin
            IO.foreach(@options.algo.to_s){|line|
              line.chomp!
              if (@hash.include?(@options.bruteforce.to_s.upcase))
                ForzeBrute::word(line, @options.wordlist, @options.bruteforce.to_s, @options.out, @options.verbose)
              end
            }
          rescue ArgumentError => e
            puts e.message
          end
        else
          if (@hash.include?(@options.bruteforce.upcase.to_s))
            ForzeBrute::word(@options.algo.to_s, @options.wordlist, @options.bruteforce.to_s, @options.out, @options.verbose)
          end
        end
      end
    end
  end
end
