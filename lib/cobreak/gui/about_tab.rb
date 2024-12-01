require 'gtk3'
require 'cobreak/info_author'
require 'cobreak/version'

module CoBreak
  module GUI
    class AboutTab < Gtk::Box
      def initialize
        super(:vertical, 20)
        self.border_width = 20
        create_widgets
      end

      private

      def hex_to_rgb(hex)
        hex = hex.gsub('#','')
        [
          hex[0..1].to_i(16) / 255.0,
          hex[2..3].to_i(16) / 255.0,
          hex[4..5].to_i(16) / 255.0
        ]
      end

      def create_widgets
        # Main container with max width
        main_container = Gtk::Box.new(:vertical, 30)
        main_container.halign = :center
        main_container.margin_top = 40
        
        # Profile section
        profile_box = Gtk::Box.new(:vertical, 20)
        profile_box.halign = :center

        # Profile image
        if pixbuf = Assets.load_image_file(File.join(Gem.path[1], "gems", "cobreak-#{CoBreak.version}", "img", "Breaker.jpg"))
          # Create a square image
          size = [pixbuf.width, pixbuf.height].min
          x_offset = (pixbuf.width - size) / 2
          y_offset = (pixbuf.height - size) / 2
          square_pixbuf = pixbuf.subpixbuf(x_offset, y_offset, size, size)
          
          # Scale to final size (slightly larger to account for padding)
          final_size = 160
          scaled_pixbuf = square_pixbuf.scale_simple(final_size, final_size, GdkPixbuf::InterpType::BILINEAR)
          
          # Create a drawing area for circular image
          drawing_area = Gtk::DrawingArea.new
          drawing_area.set_size_request(160, 160)
          
          # Handle draw event
          drawing_area.signal_connect 'draw' do |widget, cr|
            # Create circular path
            width = widget.allocated_width
            height = widget.allocated_height
            radius = [width, height].min / 2.0
            
            # Center the circle
            cr.translate(width/2, height/2)
            
            # Draw circular border
            cr.arc(0, 0, radius, 0, 2 * Math::PI)
            cr.set_source_rgb(*(hex_to_rgb(MainWindow::THEME[:accent])))
            cr.set_line_width(3)
            cr.stroke_preserve
            
            # Create circular clip
            cr.clip
            
            # Draw image
            if scaled_pixbuf
              # Center the image
              cr.translate(-radius, -radius)
              cr.set_source_pixbuf(scaled_pixbuf, 0, 0)
              cr.paint
            end
            
            true
          end
          
          # Create a centering container
          image_box = Gtk::Box.new(:horizontal, 0)
          image_box.halign = :center
          image_box.margin_bottom = 20
          image_box.pack_start(drawing_area, expand: false, fill: false, padding: 0)
          
          # Add to profile box
          profile_box.pack_start(image_box, expand: false, fill: true, padding: 0)
        end

        # Author name with large font
        name_label = Gtk::Label.new
        name_label.markup = "<span font='24' weight='bold'>#{Author.author}</span>"
        profile_box.pack_start(name_label, expand: false, fill: false, padding: 0)

        # Role/Title
        role_label = Gtk::Label.new
        role_label.markup = "<span font='12' style='italic'>Security Researcher &amp; Developer</span>"
        role_label.style_context.add_class('subtitle-label')
        profile_box.pack_start(role_label, expand: false, fill: false, padding: 0)

        main_container.pack_start(profile_box, expand: false, fill: false, padding: 0)

        # Social Links section with icons
        social_box = Gtk::Box.new(:horizontal, 20)
        social_box.halign = :center
        social_box.margin_top = 20
        social_box.margin_bottom = 30

        # Create social links with icons
        create_social_button(social_box, Assets::PORTFOLIO_ICON, "https://breakingtws.github.io", "Portfolio")
        create_social_button(social_box, Assets::EMAIL_ICON, "mailto:#{Author.email}", "Email")
        create_social_button(social_box, Assets::GITHUB_ICON, "https://github.com/BreakingTWS/CoBreak", "GitHub")

        main_container.pack_start(social_box, expand: false, fill: false, padding: 0)

        # App Info section
        info_frame = Gtk::Frame.new
        info_frame.margin_top = 20
        info_frame.style_context.add_class('frame')
        
        info_box = Gtk::Box.new(:vertical, 15)
        info_box.margin = 20
        
        # App description
        desc_label = Gtk::Label.new
        desc_label.markup = "<span font='12'>CoBreak is a comprehensive security audit and password recovery tool that includes various encryption and hashing algorithms. Built with a focus on performance and usability, it provides a powerful set of tools for security professionals and researchers.</span>"
        desc_label.line_wrap = true
        desc_label.xalign = 0
        desc_label.margin_bottom = 10
        info_box.pack_start(desc_label, expand: false, fill: true, padding: 0)

        # Version info
        version_box = Gtk::Box.new(:horizontal, 0)
        version_box.margin_top = 10
        
        version_label = Gtk::Label.new
        version_label.markup = "<span font='12' weight='bold'>Version #{CoBreak.version}</span>"
        version_box.pack_start(version_label, expand: false, fill: false, padding: 0)
        
        release_date = Gtk::Label.new
        release_date.markup = "<span font='12' style='italic'>  •  Released #{Author.date}</span>"
        version_box.pack_start(release_date, expand: false, fill: false, padding: 0)
        
        info_box.pack_start(version_box, expand: false, fill: false, padding: 0)
        
        info_frame.add(info_box)
        main_container.pack_start(info_frame, expand: false, fill: true, padding: 0)

        self.pack_start(main_container, expand: true, fill: true, padding: 0)
      end

      def create_social_button(container, icon_data, url, tooltip)
        button = Gtk::Button.new
        button.tooltip_text = tooltip
        button.style_context.add_class('social-button')
        
        # Create icon
        base64_data = icon_data.split(',')[1]
        loader = GdkPixbuf::PixbufLoader.new
        loader.write(Base64.decode64(base64_data))
        loader.close
        
        if pixbuf = loader.pixbuf
          icon = Gtk::Image.new(pixbuf: pixbuf)
          button.add(icon)
        end
        
        button.signal_connect('clicked') do
          uri = url.start_with?('@') ? "https://t.me/#{url[1..-1]}" : url
          system("xdg-open '#{uri}'")
        end
        
        container.pack_start(button, expand: false, fill: false, padding: 0)
      end
    end
  end
end
