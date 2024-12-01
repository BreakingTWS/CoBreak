#!/usr/bin/env ruby

require 'fileutils'
require 'rbconfig'

def install_desktop_entry
  puts "Installing CoBreak desktop entry..."
  
  # Obtener la ruta de la gema instalada
  gem_dir = Gem::Specification.find_by_name('cobreak').gem_dir
  
  begin
    # Crear directorio para imágenes si no existe
    FileUtils.mkdir_p '/usr/share/cobreak/img'
    
    # Copiar el icono
    FileUtils.cp(
      File.join(gem_dir, 'img', 'Breaker.jpg'),
      '/usr/share/cobreak/img/Breaker.jpg'
    )
    
    # Copiar el archivo .desktop
    FileUtils.cp(
      File.join(gem_dir, 'cobreak.desktop'),
      '/usr/share/applications/cobreak.desktop'
    )
    
    # Dar permisos de ejecución al archivo .desktop
    FileUtils.chmod 0755, '/usr/share/applications/cobreak.desktop'
    
    # Actualizar la base de datos de aplicaciones
    system('update-desktop-database /usr/share/applications') if File.exist?('/usr/share/applications')
    
    puts "CoBreak has been successfully integrated into your system menu!"
  rescue Errno::EACCES
    puts "Error: Root privileges required for menu integration."
    puts "Please run: sudo gem install cobreak"
  rescue => e
    puts "Warning: Could not install desktop entry: #{e.message}"
  end
end

# Ejecutar la instalación
install_desktop_entry if Process.uid == 0 # Solo si es root
