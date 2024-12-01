require 'gtk3'
require 'cobreak/gui/main_window'
require 'cobreak/gui/encryption_tab'
require 'cobreak/gui/attack_tab'
require 'cobreak/gui/hash_tab'

module CoBreak
  module GUI
    def self.start
      app = Gtk::Application.new('org.cobreak.app', :flags_none)

      app.signal_connect 'activate' do |application|
        begin
          window = MainWindow.new(application)
          window.window.signal_connect('destroy') { application.quit }
        rescue => e
          puts "Error starting GUI: #{e.message}"
          puts e.backtrace
          application.quit
        end
      end

      begin
        puts "Starting CoBreak #{CoBreak.version} GUI"
        print "Ctrl + C Terminate Process..."
        app.run
      rescue Interrupt => a
        puts "\nAplication Interrupt for Ctrl + C..."
      rescue => e
        puts "Error running application: #{e.message}"
        puts e.backtrace
      end
    end
  end
end
