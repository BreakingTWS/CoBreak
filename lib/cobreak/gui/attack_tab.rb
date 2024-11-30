require 'gtk3'
require 'digest'
require 'cobreak/cobreak'

module CoBreak
  module GUI
    class AttackTab < Gtk::Box
      def initialize
        super(:vertical, 20)
        self.border_width = 20
        create_widgets
      end

      private

      def create_widgets
        # Header
        #header = Gtk::Label.new
        #header.markup = "<span font='16' weight='bold'>Attack Tools</span>"
        #header.xalign = 0
        #self.pack_start(header, expand: false, fill: true, padding: 0)

        # Description
        #description = Gtk::Label.new
        #description.markup = "<span>Perform various attacks on hashes and ciphers</span>"
        #description.xalign = 0
        #self.pack_start(description, expand: false, fill: true, padding: 0)

        # Main content area
        content_box = Gtk::Box.new(:horizontal, 20)
        self.pack_start(content_box, expand: true, fill: true, padding: 0)

        # Left panel (controls)
        left_panel = Gtk::Box.new(:vertical, 15)
        left_panel.width_request = 300
        content_box.pack_start(left_panel, expand: false, fill: true, padding: 0)

        # Attack type selection
        type_frame = create_frame('Attack Type')
        left_panel.pack_start(type_frame, expand: false, fill: true, padding: 0)

        type_box = Gtk::Box.new(:vertical, 10)
        type_box.margin = 10
        type_frame.add(type_box)

        @attack_combo = Gtk::ComboBoxText.new
        attack_types = ['Dictionary Attack']
        attack_types.each { |type| @attack_combo.append_text(type) }
        @attack_combo.active = 0
        @attack_combo.signal_connect('changed') { 
          update_hash_types
          update_options_visibility
          update_status
        }
        type_box.pack_start(@attack_combo, expand: false, fill: true, padding: 0)

        # Hash type selection
        hash_frame = create_frame('Target Type')
        left_panel.pack_start(hash_frame, expand: false, fill: true, padding: 0)

        hash_box = Gtk::Box.new(:vertical, 10)
        hash_box.margin = 10
        hash_frame.add(hash_box)

        @hash_combo = Gtk::ComboBoxText.new
        hash_box.pack_start(@hash_combo, expand: false, fill: true, padding: 0)

        # Initialize hash types
        @hash_types = {
          'Dictionary Attack' => %w[MD4 MD5 HALF-MD5 SHA1 SHA2-224 SHA2-256 SHA2-384 SHA2-512 SHA3-224 SHA3-256 SHA3-384 SHA3-512 RIPEMD-160 TIGER-160 DOUBLE-SHA1 BLAKE2S-128 BLAKE2S-160 BLAKE2B-160 BLAKE2S-224 BLAKE2S-256 BLAKE2B-256 BLAKE2B-384 BLAKE2B-512 WHIRLPOOL STRIBOG-256 STRIBOG-512 SHAKE-128]
        }
        update_hash_types

        # Dictionary options
        @dict_box = Gtk::Box.new(:vertical, 10)
        hash_box.pack_start(@dict_box, expand: false, fill: true, padding: 0)

        wordlist_box = Gtk::Box.new(:horizontal, 10)
        @dict_box.pack_start(wordlist_box, expand: false, fill: true, padding: 0)

        @wordlist_entry = Gtk::Entry.new
        @wordlist_entry.editable = false
        @wordlist_entry.placeholder_text = "Select wordlist file..."
        wordlist_box.pack_start(@wordlist_entry, expand: true, fill: true, padding: 0)

        browse_button = Gtk::Button.new(label: 'Browse')
        browse_button.signal_connect('clicked') { browse_wordlist }
        wordlist_box.pack_start(browse_button, expand: false, fill: true, padding: 0)

        # Right panel (target/results)
        right_panel = Gtk::Box.new(:vertical, 15)
        content_box.pack_start(right_panel, expand: true, fill: true, padding: 0)

        # Target input
        target_frame = create_frame('Target')
        right_panel.pack_start(target_frame, expand: false, fill: true, padding: 0)

        target_box = Gtk::Box.new(:vertical, 10)
        target_box.margin = 10
        target_frame.add(target_box)

        target_label = Gtk::Label.new
        target_label.markup = '<span weight="bold">Enter target hash:</span>'
        target_label.xalign = 0
        target_box.pack_start(target_label, expand: false, fill: true, padding: 0)

        @target_entry = Gtk::Entry.new
        @target_entry.signal_connect('changed') { update_status }
        target_box.pack_start(@target_entry, expand: false, fill: true, padding: 0)

        # Results area
        results_frame = create_frame('Results')
        right_panel.pack_start(results_frame, expand: true, fill: true, padding: 0)

        results_box = Gtk::Box.new(:vertical, 10)
        results_box.margin = 10
        results_frame.add(results_box)

        @results_text = Gtk::TextView.new
        @results_text.editable = false
        @results_text.wrap_mode = :word
        
        results_scroll = Gtk::ScrolledWindow.new
        results_scroll.set_policy(:automatic, :automatic)
        results_scroll.add(@results_text)
        results_box.pack_start(results_scroll, expand: true, fill: true, padding: 0)


        # Action buttons
        button_box = Gtk::Box.new(:horizontal, 10)
        button_box.halign = :end
        right_panel.pack_start(button_box, expand: false, fill: true, padding: 10)

        @start_button = Gtk::Button.new(label: 'Start Attack')
        @start_button.signal_connect('clicked') { start_attack }
        button_box.pack_start(@start_button, expand: false, fill: true, padding: 0)

        @stop_button = Gtk::Button.new(label: 'Stop')
        @stop_button.sensitive = false
        @stop_button.signal_connect('clicked') { stop_attack }
        button_box.pack_start(@stop_button, expand: false, fill: true, padding: 0)

        clear_button = Gtk::Button.new(label: 'Clear')
        clear_button.signal_connect('clicked') { clear_fields }
        button_box.pack_start(clear_button, expand: false, fill: true, padding: 0)

        update_options_visibility
        update_status
      end

      def create_frame(title)
        frame = Gtk::Frame.new
        label = Gtk::Label.new
        label.markup = "<span weight='bold'>#{title}</span>"
        frame.label_widget = label
        frame
      end

      def update_hash_types
        @hash_combo.remove_all
        type = @attack_combo.active_text
        @hash_types[type].each { |hash_type| @hash_combo.append_text(hash_type) }
        @hash_combo.active = 0
      end

      def update_options_visibility
        type = @attack_combo.active_text
        @dict_box.visible = (type == 'Dictionary Attack')
      end

      def browse_wordlist
        dialog = Gtk::FileChooserDialog.new(
          title: 'Select Wordlist',
          parent: self.toplevel,
          action: :open,
          buttons: [
            ['Cancel', :cancel],
            ['Open', :accept]
          ]
        )

        # Add file filters
        filter_text = Gtk::FileFilter.new
        filter_text.name = "Text files"
        filter_text.add_mime_type("text/plain")
        filter_text.add_pattern("*.txt")
        filter_text.add_pattern("*.dict")
        filter_text.add_pattern("*.wordlist")
        dialog.add_filter(filter_text)

        filter_all = Gtk::FileFilter.new
        filter_all.name = "All files"
        filter_all.add_pattern("*")
        dialog.add_filter(filter_all)

        if dialog.run == :accept
          @wordlist_entry.text = dialog.filename
          show_status_message("Wordlist selected: #{File.basename(dialog.filename)}", :info)
        end

        dialog.destroy
      end

      def start_attack
        return if @attack_running

        begin
          target = @target_entry.text.strip
          return show_error_dialog("Please enter a target hash") if target.empty?

          type = @attack_combo.active_text
          hash_type = @hash_combo.active_text

          if type == 'Dictionary Attack'
            return show_error_dialog("Please select a wordlist file") if @wordlist_entry.text.empty?

            # Validate hash format based on type
            expected_length = case hash_type
            when 'MD5'
              32
            when 'SHA1'
              40
            when 'SHA256'
              64
            end

            #unless target =~ /\A[a-fA-F0-9]{#{expected_length}}\z/
            #  return show_error_dialog("Invalid #{hash_type} hash format. Expected #{expected_length} hexadecimal characters.")
            #end

            wordlist = @wordlist_entry.text
            
            unless File.exist?(wordlist)
              show_error_dialog("Wordlist file not found: #{wordlist}")
              return
            end
            
            unless File.readable?(wordlist)
              show_error_dialog("Cannot read wordlist file: #{wordlist}. Please check file permissions.")
              return
            end

            @attack_running = true
            @start_button.sensitive = false
            @stop_button.sensitive = true

            append_result("Starting dictionary attack...")
            append_result("Using wordlist: #{wordlist}")

            # Start attack in a thread to keep UI responsive
            Thread.new do
              begin

                # Try to crack using AttackWordlist module
                result = case hash_type
                when 'MD4'
                  CoBreak::AttackWordlist::MD4.crack(target, wordlist)
                when 'MD5'
                  CoBreak::AttackWordlist::MD5.crack(target, wordlist)
                when 'MD5'
                  CoBreak::AttackWordlist::HALF_MD5.crack(target, wordlist)
                when 'SHA1'
                  CoBreak::AttackWordlist::SHA1.crack(target, wordlist)
                when 'DOUBLE_SHA1'
                  CoBreak::AttackWordlist::DOUBLE_SHA1.crack(target, wordlist)
                when 'SHA2-224'
                  CoBreak::AttackWordlist::SHA2_224.crack(target, wordlist)
                when 'SHA2-256'
                  CoBreak::AttackWordlist::SHA2_256.crack(target, wordlist)
                when 'SHA2-384'
                  CoBreak::AttackWordlist::SHA2_384.crack(target, wordlist)
                when 'SHA2-512'
                  CoBreak::AttackWordlist::SHA2_512.crack(target, wordlist)
                when 'SHA2-256'
                  CoBreak::AttackWordlist::SHA2_256.crack(target, wordlist)
                when 'SHA3-224'
                  CoBreak::AttackWordlist::SHA2_224.crack(target, wordlist)
                when 'SHA3-256'
                  CoBreak::AttackWordlist::SHA3_256.crack(target, wordlist)
                when 'SHA3-384'
                  CoBreak::AttackWordlist::SHA3_384.crack(target, wordlist)
                when 'SHA3-512'
                  CoBreak::AttackWordlist::SHA3_512.crack(target, wordlist)
                when 'RIPEMD-160'
                  CoBreak::AttackWordlist::RIPEMD_160.crack(target, wordlist)
                when 'TIGER-160'
                  CoBreak::AttackWordlist::TIGER_160.crack(target, wordlist)
                when 'BLAKE2S-128'
                  CoBreak::AttackWordlist::BLAKE2S_128.crack(target, wordlist)
                when 'BLAKE2S-160'
                  CoBreak::AttackWordlist::BLAKE2S_160.crack(target, wordlist)
                when 'BLAKE2B-160'
                  CoBreak::AttackWordlist::BLAKE2B_160.crack(target, wordlist)
                when 'BLAKE2S-224'
                  CoBreak::AttackWordlist::BLAKE2S_224.crack(target, wordlist)
                when 'BLAKE2S-256'
                  CoBreak::AttackWordlist::BLAKE2S_256.crack(target, wordlist)
                when 'BLAKE2B-256'
                  CoBreak::AttackWordlist::BLAKE2B_256.crack(target, wordlist)
                when 'BLAKE2B-384'
                  CoBreak::AttackWordlist::BLAKE2B_384.crack(target, wordlist)
                when 'BLAKE2B-512'
                  CoBreak::AttackWordlist::BLAKE2B_512.crack(target, wordlist)
                when 'WHIRLPOOL'
                  CoBreak::AttackWordlist::WHIRLPOOL.crack(target, wordlist)
                when 'STRIBOG-256'
                  CoBreak::AttackWordlist::STRIBOG_256.crack(target, wordlist)
                when 'STRIBOG-512'
                  CoBreak::AttackWordlist::STRIBOG_512.crack(target, wordlist)
                end

                GLib::Idle.add do
                  if result
                    append_result("\nPassword found!")
                    append_result("Password: #{result}")
                  else
                    append_result("\nNo password found")
                  end

                  @attack_running = false
                  stop_attack
                  false
                end
              rescue => e
                puts "Error during crack attempt: #{e.class}: #{e.message}"  # Debug output
                puts e.backtrace.join("\n")  # Debug output
                GLib::Idle.add do
                  show_error_dialog("Error during attack: #{e.message}")
                  stop_attack
                  false
                end
              end
            end

            show_status_message("Attack started: #{type} using #{hash_type}", :info)
          else
            show_error_dialog("#{type} not implemented yet")
          end
        rescue => e
          show_error_dialog("Error starting attack: #{e.message}")
          stop_attack
        end
      end

      def stop_attack
        was_running = @attack_running
        @attack_running = false
        
        GLib::Idle.add do
          @start_button.sensitive = true
          @stop_button.sensitive = false
          if was_running && !@progress_bar.text.include?("100%")
            append_result("\nAttack stopped by user")
            show_status_message("Attack stopped by user", :info)
          end
          false
        end

      end

      def clear_fields
        @target_entry.text = ''
        @wordlist_entry.text = ''
        @results_text.buffer.text = ''
        show_status_message("Fields cleared", :info)
      end

      def append_result(text)
        buffer = @results_text.buffer
        buffer.insert(buffer.end_iter, "#{text}\n")
        mark = buffer.create_mark(nil, buffer.end_iter, false)
        @results_text.scroll_mark_onscreen(mark)
        buffer.delete_mark(mark)
      end

      def update_status
        type = @attack_combo.active_text
        algo = @hash_combo.active_text
        target = @target_entry.text.strip
        
        status = "Ready to perform #{type} using #{algo}"
        status += target.empty? ? "" : " | Target length: #{target.length}"
        
        show_status_message(status, :info)
      end

      def show_error_dialog(message)
        dialog = Gtk::MessageDialog.new(
          parent: self.toplevel,
          flags: :destroy_with_parent,
          type: :error,
          buttons: :close,
          message: message
        )
        dialog.run
        dialog.destroy
        show_status_message(message, :error)
      end

      def show_status_message(message, type)
        return unless self.toplevel.is_a?(Gtk::Window)
        
        status_bar = self.toplevel.children.first.children.last
        return unless status_bar.is_a?(Gtk::Statusbar)
        
        context_id = status_bar.get_context_id('main')
        status_bar.pop(context_id)
        status_bar.push(context_id, message)
      end
    end
  end
end
