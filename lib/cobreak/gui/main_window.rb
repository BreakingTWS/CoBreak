require 'gtk3'
require 'cobreak/gui/encryption_tab'
require 'cobreak/gui/attack_tab'
require 'cobreak/gui/hash_tab'
require 'cobreak/gui/about_tab'
require 'cobreak/version'
require 'cobreak/info_author'
require 'cobreak/gui/assets'

module CoBreak
  module GUI
    class MainWindow
      attr_reader :window

      THEME = {
        'background': '#1a1b26',
        'sidebar': '#16161e',
        'accent': '#7aa2f7',
        'accent_hover': '#91b3ff',
        'text': '#c0caf5',
        'border': '#24283b',
        'hover': '#414868',
        'success': '#9ece6a',
        'error': '#f7768e'
      }

      def initialize(application)
        @window = Gtk::ApplicationWindow.new(application)
        @window.title = "CoBreak #{CoBreak.version}"
        @window.set_default_size(1200, 600)
        @window.window_position = :center
        
        # Set window icon
        set_window_icon

        @window.set_size_request(800, 400)

        # Apply custom CSS
        apply_custom_styles

        scrolled = Gtk::ScrolledWindow.new
        scrolled.set_policy(:automatic, :automatic)
        @window.add(scrolled)

        main_box = Gtk::Box.new(:horizontal, 0)
        scrolled.add(main_box)

        create_sidebar(main_box)

        create_content_area(main_box)

        @window.show_all
      end

      private

      def set_window_icon
        # Load the app icon
        icon_data = Assets::APP_ICON
        pixbuf = create_pixbuf_from_data(icon_data)
        @window.icon = pixbuf if pixbuf
      end

      def create_icon_from_data(icon_data)
        pixbuf = create_pixbuf_from_data(icon_data)
        Gtk::Image.new(pixbuf: pixbuf)
      end

      def create_pixbuf_from_data(icon_data)
        # Extract base64 data from data URL
        base64_data = icon_data.split(',')[1]
        loader = GdkPixbuf::PixbufLoader.new
        loader.write(Base64.decode64(base64_data))
        loader.close
        loader.pixbuf
      rescue => e
        puts "Error loading icon: #{e.message}"
        nil
      end


      def apply_custom_styles
        css_provider = Gtk::CssProvider.new
        css_provider.load(data: <<~CSS)
          window {
            background-color: #{THEME[:background]};
            color: #{THEME[:text]};
          }

          .sidebar {
            background-color: #{THEME[:sidebar]};
            color: #{THEME[:text]};
            border-right: 1px solid #{THEME[:border]};
          }

          .sidebar button {
            background: none;
            border: none;
            border-radius: 0;
            padding: 15px 20px;
            margin: 5px 10px;
            color: #{THEME[:text]};
            transition: all 200ms ease;
          }

          .sidebar button box {
            margin: 0 8px;
          }

          .sidebar button image {
            margin-right: 8px;
          }

          .sidebar button label {
            margin-left: 8px;
          }

          .sidebar button:hover {
            background-color: #{THEME[:hover]};
            border-radius: 6px;
          }

          .sidebar button.active {
            background-color: #{THEME[:accent]};
            color: #{THEME[:background]};
            border-radius: 6px;
          }

          .content-area {
            background-color: #{THEME[:background]};
            padding: 20px;
            min-height: 600px;
          }

          .content-area scrolledwindow {
            margin: 10px 0;
          }

          frame {
            border: 1px solid #{THEME[:border]};
            border-radius: 8px;
            padding: 10px;
            margin: 10px;
            background-color: #{THEME[:sidebar]};
          }

          frame > label {
            color: #{THEME[:accent]};
            margin: 5px 10px;
          }

          entry {
            background-color: #{THEME[:background]};
            color: #{THEME[:text]};
            border: 1px solid #{THEME[:border]};
            border-radius: 6px;
            padding: 8px;
          }

          textview {
            background-color: #{THEME[:background]};
            color: #{THEME[:text]};
          }

          textview text {
            background-color: #{THEME[:background]};
            color: #{THEME[:text]};
          }

          button {
            background-color: #{THEME[:accent]};
            color: #{THEME[:background]};
            border: none;
            border-radius: 6px;
            padding: 10px 20px;
            transition: all 200ms ease;
          }

          button:hover {
            background-color: #{THEME[:accent_hover]};
          }

          combobox button {
            background-color: #{THEME[:background]};
            color: #{THEME[:text]};
            border: 1px solid #{THEME[:border]};
          }

          .header-title {
            color: #{THEME[:accent]};
            font-size: 24px;
            font-weight: bold;
            margin: 10px;
          }

          progressbar {
            border-radius: 4px;
          }

          progressbar trough {
            background-color: #{THEME[:border]};
            border-radius: 4px;
          }

          progressbar progress {
            background-color: #{THEME[:accent]};
            border-radius: 4px;
          }

          scrollbar {
            background-color: #{THEME[:border]};
            border-radius: 4px;
          }

          scrollbar slider {
            background-color: #{THEME[:accent]};
            border-radius: 4px;
            min-width: 8px;
            min-height: 8px;
          }

          scrollbar slider:hover {
            background-color: #{THEME[:accent_hover]};
          }

          scrolledwindow {
            min-height: 200px;
          }

          .status-bar {
            background-color: #{THEME[:sidebar]};
            color: #{THEME[:text]};
            padding: 5px 10px;
            border-top: 1px solid #{THEME[:border]};
          }

          .info-label {
            color: #{THEME[:accent]};
            font-weight: bold;
          }

          frame {
            margin-bottom: 15px;
          }

          frame > label {
            margin: 0 10px;
            padding: 0 5px;
            background-color: #{THEME[:sidebar]};
          }

          button.link {
            padding: 0;
          }

          button.link:hover {
            background: none;
            text-decoration: underline;
          }

          .social-button {
            background: #{THEME[:sidebar]};
            border: 2px solid #{THEME[:accent]};
            border-radius: 50%;
            padding: 10px;
            margin: 0 8px;
            min-width: 48px;
            min-height: 48px;
          }

          .social-button:hover {
            background-color: #{THEME[:accent]};
            border-color: #{THEME[:accent_hover]};
          }

          .social-button image {
            opacity: 0.85;
          }

          .social-button:hover image {
            opacity: 1;
          }

          .subtitle-label {
            color: #{THEME[:text]};
            opacity: 0.8;
          }

        CSS

        Gtk::StyleContext.add_provider_for_screen(
          Gdk::Screen.default,
          css_provider,
          Gtk::StyleProvider::PRIORITY_APPLICATION
        )
      end

      def create_sidebar(main_box)
        sidebar = Gtk::Box.new(:vertical, 0)
        sidebar.style_context.add_class('sidebar')
        sidebar.width_request = 200
        main_box.pack_start(sidebar, expand: false, fill: true, padding: 0)

        # Logo and title
        logo_box = Gtk::Box.new(:vertical, 5)
        logo_box.margin = 20
        sidebar.pack_start(logo_box, expand: false, fill: true, padding: 0)

        title = Gtk::Label.new
        title.markup = "<span font='20' weight='bold'>CoBreak</span>"
        title.style_context.add_class('header-title')
        logo_box.pack_start(title, expand: false, fill: true, padding: 0)

        version = Gtk::Label.new("v#{CoBreak.version}")
        version.style_context.add_class('version-label')
        logo_box.pack_start(version, expand: false, fill: true, padding: 0)

        # Navigation buttons with icons
        @nav_buttons = {}
        nav_items = [
          ['Cipher', Assets::CIPHER_ICON],
          ['Attack Tools', Assets::ATTACK_ICON],
          ['Encrypt Algoritms', Assets::ENCRYPT_ICON],
          ['About', Assets::ABOUT_ICON]
        ]

        nav_items.each do |name, icon_data|
          # Create button with icon and label
          btn_box = Gtk::Box.new(:horizontal, 8)
          
          # Create and add icon
          icon = create_icon_from_data(icon_data)
          btn_box.pack_start(icon, expand: false, fill: false, padding: 0)
          
          # Add label
          label = Gtk::Label.new(name)
          label.xalign = 0 # Left align text
          btn_box.pack_start(label, expand: true, fill: true, padding: 0)
          
          # Create button and add box
          btn = Gtk::Button.new
          btn.add(btn_box)
          
          btn.signal_connect('clicked') { switch_tab(name) }
          sidebar.pack_start(btn, expand: false, fill: true, padding: 0)
          @nav_buttons[name] = btn
        end

        # Set first button as active
        @nav_buttons['Cipher'].style_context.add_class('active')
      end

      def create_content_area(main_box)
        # Create scrolled window for content
        content_scroll = Gtk::ScrolledWindow.new
        content_scroll.set_policy(:automatic, :automatic)
        main_box.pack_start(content_scroll, expand: true, fill: true, padding: 0)

        # Create content box inside scroll
        @content_box = Gtk::Box.new(:vertical, 0)
        @content_box.style_context.add_class('content-area')
        content_scroll.add(@content_box)

        # Create stack for switching between tabs
        @stack = Gtk::Stack.new
        @stack.transition_type = :slide_left_right
        @stack.transition_duration = 200
        @content_box.pack_start(@stack, expand: true, fill: true, padding: 0)

        # Add pages to stack
        @stack.add_named(EncryptionTab.new, 'Cipher')
        @stack.add_named(AttackTab.new, 'Attack Tools')
        @stack.add_named(HashTab.new, 'Encrypt Algoritms')
        @stack.add_named(AboutTab.new, 'About')

        # Create status bar (outside scroll area)
        status_bar = Gtk::Statusbar.new
        status_bar.style_context.add_class('status-bar')
        @content_box.pack_end(status_bar, expand: false, fill: true, padding: 0)
      end

      def switch_tab(name)
        @nav_buttons.each do |btn_name, btn|
          if btn_name == name
            btn.style_context.add_class('active')
          else
            btn.style_context.remove_class('active')
          end
        end
        @stack.visible_child_name = name
      end
    end
  end
end
