require "cobreak/version"
module CoBreak
    class BruteCipher
        def initialize(options)
            @options = options
            @cipher = %w[Cesar Vigenere]
        end
        begin
            require 'cobreak/force'
          rescue LoadError => e
            puts e.message
            abort "reinstall gem new"
          end
        def banner_cipher()
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
    end
end