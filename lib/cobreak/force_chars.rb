require 'ostruct'
require 'ruby_figlet'
using RubyFiglet
module CoBreak
  class BruteChars
    def initialize(options)
      @options = options
      @hash = %w[MD4 MD5 SHA1 SHA224 SHA256 SHA384 SHA512 RIPEMD160]
    end
    def banner_chars()
      puts "\e[0;31m"
      puts "cobreak".art("Bloody")
      puts "\e[0m"
      puts "\e[1;32m╭─[\e[1;37m CoBreak: #{CoBreak.version}"
      unless (@options.range.nil?)
        puts "\e[32m├─[\e[1;37m Range: #{@options.range[0]} #{@options.range[1]}"
      else
        puts "\e[31m├─[\e[1;37m Range Not Found"
      end
      unless (@options.chars.nil?) or (@options.chars.empty?)
        puts "\e[32m├─[\e[1;37m Characters: #{@options.chars}"
      else
        puts "\e[31m├─[\e[1;37m Characters Not Found"
      end
      if (@hash.include?(@options.bruteforce.to_s.upcase))
        puts "\e[32m├─[\e[1;37m Type Hash: #{@options.bruteforce.upcase}"
      else
        puts "\e[31m├─[\e[1;37m Type Hash Not Found"
      end
      unless (@options.algo.nil?) or (@options.algo.empty?)
        puts "\e[32m╰─[\e[1;37m Hash: #{@options.algo}\n\n"
      else
        puts "\e[31m╰─[\e[1;37m Hash Not Found"
      end
    end
    def chars()
#      if (@options.range.empty?) or (@options.chars.nil?) or (@param.algo.nil?)
#         abort "\n"
#      end
      if (@hash.include?(@options.bruteforce.upcase))
        if (File.exists?(@options.algo.to_s))
          IO.foreach(@options.algo){|line|
            line.chomp!
            ForzeBrute::chars(line, @options.range, @options.chars, @options.bruteforce, @options.out, @options.verbose)
          }
        else
          if (@hash.include?(@options.bruteforce.upcase))
            ForzeBrute::chars(@options.algo, @options.range, @options.chars, @options.bruteforce, @options.out, @options.verbose)
          end
        end
      end
    end
  end
end
