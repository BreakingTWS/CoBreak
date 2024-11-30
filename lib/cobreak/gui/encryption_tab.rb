require 'gtk3'
require 'cobreak/cobreak'

module CoBreak
  module GUI
    class EncryptionTab < Gtk::Box
      def initialize
        super(:vertical, 20)
        self.border_width = 20
        create_widgets
      end

      private

      def create_widgets
        # Header
        #header = Gtk::Label.new
        #header.markup = "<span font='16' weight='bold'>Encryption and Decryption</span>"
        #header.xalign = 0
        #self.pack_start(header, expand: false, fill: true, padding: 0)

        # Description
        #description = Gtk::Label.new
        #description.markup = "<span>Encrypt or decrypt your data using various algorithms</span>"
        #description.xalign = 0
        #self.pack_start(description, expand: false, fill: true, padding: 0)

        # Main content area
        content_box = Gtk::Box.new(:horizontal, 20)
        self.pack_start(content_box, expand: true, fill: true, padding: 0)

        # Left panel (controls)
        left_panel = Gtk::Box.new(:vertical, 15)
        left_panel.width_request = 300
        content_box.pack_start(left_panel, expand: false, fill: true, padding: 0)

        # Mode selection with modern toggle buttons
        mode_frame = create_frame('Operation Mode')
        left_panel.pack_start(mode_frame, expand: false, fill: true, padding: 0)

        mode_box = Gtk::Box.new(:horizontal, 10)
        mode_box.margin = 10
        mode_frame.add(mode_box)

        @mode = 'encode'
        encrypt_radio = create_radio('Encrypt', true)
        decrypt_radio = create_radio('Decrypt', false, encrypt_radio)

        encrypt_radio.signal_connect('toggled') { 
          @mode = 'encode' if encrypt_radio.active?
          update_status
        }
        decrypt_radio.signal_connect('toggled') { 
          @mode = 'decode' if decrypt_radio.active?
          update_status
        }

        mode_box.pack_start(encrypt_radio, expand: true, fill: true, padding: 5)
        mode_box.pack_start(decrypt_radio, expand: true, fill: true, padding: 5)

        # Algorithm selection
        algo_frame = create_frame('Algorithm')
        left_panel.pack_start(algo_frame, expand: false, fill: true, padding: 0)

        algo_box = Gtk::Box.new(:vertical, 10)
        algo_box.margin = 10
        algo_frame.add(algo_box)

        @cipher_combo = Gtk::ComboBoxText.new
        cipher_types = ['Base64', 'Base32', 'Base16', 'Binary', 'Cesar', 'Vigenere']
        cipher_types.each { |type| @cipher_combo.append_text(type) }
        @cipher_combo.active = 0
        @cipher_combo.signal_connect('changed') { 
          update_options_visibility
          update_status
        }
        algo_box.pack_start(@cipher_combo, expand: false, fill: true, padding: 0)

        # Cipher-specific options
        @options_frame = create_frame('Options')
        left_panel.pack_start(@options_frame, expand: false, fill: true, padding: 0)

        @options_box = Gtk::Box.new(:vertical, 10)
        @options_box.margin = 10
        @options_frame.add(@options_box)

        # Cesar cipher options
        @cesar_box = Gtk::Box.new(:vertical, 10)
        @options_box.pack_start(@cesar_box, expand: false, fill: true, padding: 0)

        rotation_box = Gtk::Box.new(:horizontal, 10)
        @cesar_box.pack_start(rotation_box, expand: false, fill: true, padding: 0)

        rotation_label = Gtk::Label.new
        rotation_label.markup = '<span weight="bold">Rotation:</span>'
        rotation_box.pack_start(rotation_label, expand: false, fill: true, padding: 0)

        @rotation_spin = Gtk::SpinButton.new(1.0, 25.0, 1.0)
        @rotation_spin.value = 3
        rotation_box.pack_start(@rotation_spin, expand: true, fill: true, padding: 0)

        # Vigenere cipher options
        @vigenere_box = Gtk::Box.new(:vertical, 10)
        @options_box.pack_start(@vigenere_box, expand: false, fill: true, padding: 0)

        key_box = Gtk::Box.new(:horizontal, 10)
        @vigenere_box.pack_start(key_box, expand: false, fill: true, padding: 0)

        key_label = Gtk::Label.new
        key_label.markup = '<span weight="bold">Key:</span>'
        key_box.pack_start(key_label, expand: false, fill: true, padding: 0)

        @key_entry = Gtk::Entry.new
        key_box.pack_start(@key_entry, expand: true, fill: true, padding: 0)

        # Action buttons
        button_box = Gtk::Box.new(:horizontal, 10)
        button_box.margin_top = 20
        left_panel.pack_start(button_box, expand: false, fill: true, padding: 0)

        process_button = Gtk::Button.new(label: 'Process')
        process_button.signal_connect('clicked') { process_text }
        button_box.pack_start(process_button, expand: true, fill: true, padding: 0)

        clear_button = Gtk::Button.new(label: 'Clear')
        clear_button.signal_connect('clicked') { clear_fields }
        button_box.pack_start(clear_button, expand: true, fill: true, padding: 0)

        # Right panel (input/output)
        right_panel = Gtk::Box.new(:vertical, 15)
        content_box.pack_start(right_panel, expand: true, fill: true, padding: 0)

        # Input area
        input_frame = create_frame('Input')
        right_panel.pack_start(input_frame, expand: true, fill: true, padding: 0)

        input_box = Gtk::Box.new(:vertical, 10)
        input_box.margin = 10
        input_frame.add(input_box)

        @input_text = Gtk::TextView.new
        @input_text.wrap_mode = :word
        @input_text.accepts_tab = false
        @input_text.buffer.signal_connect('changed') { update_status }
        
        input_scroll = Gtk::ScrolledWindow.new
        input_scroll.set_policy(:automatic, :automatic)
        input_scroll.add(@input_text)
        input_box.pack_start(input_scroll, expand: true, fill: true, padding: 0)

        # Output area
        output_frame = create_frame('Output')
        right_panel.pack_start(output_frame, expand: true, fill: true, padding: 0)

        output_box = Gtk::Box.new(:vertical, 10)
        output_box.margin = 10
        output_frame.add(output_box)

        @output_text = Gtk::TextView.new
        @output_text.editable = false
        @output_text.wrap_mode = :word
        
        output_scroll = Gtk::ScrolledWindow.new
        output_scroll.set_policy(:automatic, :automatic)
        output_scroll.add(@output_text)
        output_box.pack_start(output_scroll, expand: true, fill: true, padding: 0)

        # Copy button for output
        copy_button = Gtk::Button.new(label: 'Copy Output')
        copy_button.signal_connect('clicked') { copy_output }
        output_box.pack_start(copy_button, expand: false, fill: false, padding: 0)

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

      def create_radio(label, is_first, group = nil)
        radio = if is_first
          Gtk::RadioButton.new(label: label)
        else
          Gtk::RadioButton.new(member: group, label: label)
        end
        radio
      end

      def update_options_visibility
        cipher_type = @cipher_combo.active_text
        @cesar_box.visible = (cipher_type == 'Cesar')
        @vigenere_box.visible = (cipher_type == 'Vigenere')
        @options_frame.visible = ['Cesar', 'Vigenere'].include?(cipher_type)
      end

      def process_text
        begin
          input = @input_text.buffer.text
          cipher_type = @cipher_combo.active_text

          # Get the appropriate cipher class
          cipher_class = case cipher_type
          when 'Base16'
            CoBreak::Cipher::Base16
          when 'Base32'
            CoBreak::Cipher::Base32
          when 'Base64'
            CoBreak::Cipher::Base64
          when 'Binary'
            CoBreak::Cipher::Binary
          when 'Cesar'
            CoBreak::Cipher::Cesar
          when 'Vigenere'
            CoBreak::Cipher::Vigenere
          end

          # Process the text
          result = if cipher_type == 'Cesar'
            cipher_class.send(@mode, input, @rotation_spin.value.to_i)
          elsif cipher_type == 'Vigenere'
            key = @key_entry.text
            return show_error_dialog("Please enter a key") if key.empty?
            cipher_class.send(@mode, input, key)
          else
            cipher_class.send(@mode, input)
          end

          @output_text.buffer.text = result.to_s
          show_status_message("#{@mode.capitalize} operation completed successfully", :success)
        rescue => e
          show_error_dialog("Error processing text: #{e.message}")
        end
      end

      def clear_fields
        @input_text.buffer.text = ''
        @output_text.buffer.text = ''
        show_status_message("Fields cleared", :info)
      end

      def copy_output
        clipboard = Gtk::Clipboard.get(Gdk::Selection::CLIPBOARD)
        clipboard.text = @output_text.buffer.text
        show_status_message("Output copied to clipboard", :info)
      end

      def update_status
        mode_text = @mode.capitalize
        algo_text = @cipher_combo.active_text
        input_length = @input_text.buffer.text.length
        
        status = "Ready to #{mode_text} using #{algo_text}"
        status += input_length > 0 ? " | Input: #{input_length} characters" : ""
        
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
