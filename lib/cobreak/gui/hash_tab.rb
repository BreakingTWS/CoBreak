require 'gtk3'
require 'cobreak/cobreak'

module CoBreak
  module GUI
    class HashTab < Gtk::Box
      def initialize
        super(:vertical, 20)
        self.border_width = 20
        create_widgets(self)
      end

      private

      def create_widgets(main_box)
        # Header
        #header = Gtk::Label.new
        #header.markup = "<span font='16' weight='bold'>Hash Functions</span>"
        #header.xalign = 0
        #main_box.pack_start(header, expand: false, fill: true, padding: 0)

        # Description
        #description = Gtk::Label.new
        #description.markup = "<span>Calculate hash values using various algorithms</span>"
        #description.xalign = 0
        #main_box.pack_start(description, expand: false, fill: true, padding: 0)

        # Main content area
        content_box = Gtk::Box.new(:horizontal, 20)
        main_box.pack_start(content_box, expand: true, fill: true, padding: 0)

        # Left panel (controls)
        left_panel = Gtk::Box.new(:vertical, 15)
        left_panel.width_request = 300
        content_box.pack_start(left_panel, expand: false, fill: true, padding: 0)

        # Input method selection
        input_frame = create_frame('Input Method')
        left_panel.pack_start(input_frame, expand: false, fill: true, padding: 0)

        input_box = Gtk::Box.new(:vertical, 10)
        input_box.margin = 10
        input_frame.add(input_box)

        @input_method = 'text'
        text_radio = create_radio('Text Input', true)
        file_radio = create_radio('File Input', false, text_radio)

        input_box.pack_start(text_radio, expand: false, fill: true, padding: 0)
        input_box.pack_start(file_radio, expand: false, fill: true, padding: 0)

        # Hash algorithm selection
        algo_frame = create_frame('Hash Algorithm')
        left_panel.pack_start(algo_frame, expand: false, fill: true, padding: 0)

        algo_box = Gtk::Box.new(:vertical, 10)
        algo_box.margin = 10
        algo_frame.add(algo_box)

        @hash_combo = Gtk::ComboBoxText.new
        hash_types = [
          'MD4', 'MD5', 'TIGER-160', 'DOUBLE-SHA1',
          'BLAKE2S-128', 'BLAKE2S-160', 'BLAKE2B-160',
          'BLAKE2S-224', 'BLAKE2S-256', 'BLAKE2B-256',
          'BLAKE2B-384', 'BLAKE2B-512', 'WHIRLPOOL',
          'GOST-STREEBOG-256', 'GOST-STREEBOG-512', 'SHAKE-128'
        ]
        hash_types.each { |type| @hash_combo.append_text(type) }
        @hash_combo.active = 0
        algo_box.pack_start(@hash_combo, expand: false, fill: true, padding: 0)

        # File chooser
        @file_chooser = Gtk::FileChooserButton.new(
          "Select a file",
          Gtk::FileChooserAction::OPEN
        )
        @file_chooser.margin_top = 10
        @file_chooser.signal_connect('file-set') do
          file_path = @file_chooser.filename
          show_status_message("Selected file: #{File.basename(file_path)}", :info)
        end
        algo_box.pack_start(@file_chooser, expand: false, fill: true, padding: 0)

        # Action buttons
        button_box = Gtk::Box.new(:horizontal, 10)
        button_box.margin_top = 20
        left_panel.pack_start(button_box, expand: false, fill: true, padding: 0)

        calculate_button = Gtk::Button.new(label: 'Calculate Hash')
        calculate_button.signal_connect('clicked') { calculate_hash }
        button_box.pack_start(calculate_button, expand: true, fill: true, padding: 0)

        clear_button = Gtk::Button.new(label: 'Clear')
        clear_button.signal_connect('clicked') { clear_fields }
        button_box.pack_start(clear_button, expand: true, fill: true, padding: 0)

        # Right panel (input/output)
        right_panel = Gtk::Box.new(:vertical, 15)
        content_box.pack_start(right_panel, expand: true, fill: true, padding: 0)

        # Input text area
        input_frame = create_frame('Input Text')
        right_panel.pack_start(input_frame, expand: true, fill: true, padding: 0)

        input_box = Gtk::Box.new(:vertical, 10)
        input_box.margin = 10
        input_frame.add(input_box)

        @input_text = Gtk::TextView.new
        @input_text.wrap_mode = :word
        
        input_scroll = Gtk::ScrolledWindow.new
        input_scroll.set_policy(:automatic, :automatic)
        input_scroll.add(@input_text)
        input_box.pack_start(input_scroll, expand: true, fill: true, padding: 0)

        # Result area
        result_frame = create_frame('Hash Result')
        right_panel.pack_start(result_frame, expand: false, fill: true, padding: 0)

        @result_box = Gtk::Box.new(:vertical, 10)
        @result_box.margin = 10
        result_frame.add(@result_box)

        @result_text = Gtk::TextView.new
        @result_text.editable = false
        @result_text.wrap_mode = :word
        @result_text.height_request = 100
        
        result_scroll = Gtk::ScrolledWindow.new
        result_scroll.set_policy(:automatic, :automatic)
        result_scroll.add(@result_text)
        @result_box.pack_start(result_scroll, expand: true, fill: true, padding: 0)

        # Add copy button to result box
        copy_button = Gtk::Button.new(label: 'Copy Result')
        copy_button.signal_connect('clicked') { copy_result }
        @result_box.pack_start(copy_button, expand: false, fill: false, padding: 5)

        # Connect radio button signals after widgets are created
        text_radio.signal_connect('toggled') do
          if text_radio.active?
            @input_method = 'text'
            @input_text.sensitive = true
            @file_chooser.sensitive = false
          end
        end
        
        file_radio.signal_connect('toggled') do
          if file_radio.active?
            @input_method = 'file'
            @input_text.sensitive = false
            @file_chooser.sensitive = true
          end
        end

        # Set initial widget states
        @input_text.sensitive = true
        @file_chooser.sensitive = false
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

      def calculate_hash
        begin
          input = if @input_method == 'text'
            text = @input_text.buffer.text
            text
          else
            file_path = @file_chooser.filename
            return show_error_dialog("Please select a file") unless file_path
            File.read(file_path)
          end

          return show_error_dialog("No input provided") if input.empty?

          hash_type = @hash_combo.active_text

          # Get the appropriate hash class from GCrypt module
          hash_class = case hash_type
          when 'MD4'
            CoBreak::GCrypt::MD4
          when 'MD5'
            CoBreak::GCrypt::MD5
          when 'TIGER-160'
            CoBreak::GCrypt::TIGER_160
          when 'DOUBLE-SHA1'
            CoBreak::GCrypt::DOUBLE_SHA1
          when 'BLAKE2S-128'
            CoBreak::GCrypt::BLAKE2S_128
          when 'BLAKE2S-160'
            CoBreak::GCrypt::BLAKE2S_160
          when 'BLAKE2B-160'
            CoBreak::GCrypt::BLAKE2B_160
          when 'BLAKE2S-224'
            CoBreak::GCrypt::BLAKE2S_224
          when 'BLAKE2S-256'
            CoBreak::GCrypt::BLAKE2S_256
          when 'BLAKE2B-256'
            CoBreak::GCrypt::BLAKE2B_256
          when 'BLAKE2B-384'
            CoBreak::GCrypt::BLAKE2B_384
          when 'BLAKE2B-512'
            CoBreak::GCrypt::BLAKE2B_512
          when 'WHIRLPOOL'
            CoBreak::GCrypt::WHIRLPOOL
          when 'GOST-STREEBOG-256'
            CoBreak::GCrypt::GOST_STREEBOG_256
          when 'GOST-STREEBOG-512'
            CoBreak::GCrypt::GOST_STREEBOG_512
          when 'SHAKE-128'
            CoBreak::GCrypt::SHAKE_128
          end

          result = if hash_class == CoBreak::GCrypt::SHAKE_128
            hash_class.hexdigest(input, 128)
          else
            hash_class.hexdigest(input)
          end

          @result_text.buffer.text = result
          show_status_message("Hash calculation completed successfully", :success)
        rescue => e
          show_error_dialog("Error calculating hash: #{e.message}")
        end
      end

      def clear_fields
        @input_text.buffer.text = ''
        @result_text.buffer.text = ''
        show_status_message("Fields cleared", :info)
      end

      def copy_result
        clipboard = Gtk::Clipboard.get(Gdk::Selection::CLIPBOARD)
        clipboard.text = @result_text.buffer.text
        show_status_message("Result copied to clipboard", :info)
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
