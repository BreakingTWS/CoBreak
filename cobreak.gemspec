Gem::Specification.new do |info|
  info.name        = 'cobreak'
  info.version     = '1.0.5'
  info.executables << "cobreak" 
  info.executables << "cbrdb"
  info.description = "The CoBreak script is an cipher and cryptography tool"
  info.add_development_dependency "bundler", "~> 2.3"
  info.add_development_dependency "sequel", "~> 5.44.0"
  info.add_development_dependency "sqlite3", '~> 1.4', '>= 1.4.0'
  info.add_runtime_dependency "sqlite3", '~> 1.4', '>= 1.4.0'
  info.add_runtime_dependency "gtk3", '~> 3.4'
  info.add_runtime_dependency "ruby_figlet"
  info.authors     = ["BreakerTW"]
  info.email       = 'breakingtws@gmail.com'
  info.summary     = "Force Brute, Cipher, Cryptography"

  # Extensiones y hooks de instalación
  info.extensions = %w[ext/cobreak/extconf.rb]
  
  # Incluir todos los archivos necesarios
  info.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(/^.gitignore/)
  end
  
  # Asegurarse de incluir los archivos del sistema
  info.files += [
    'cobreak.desktop',
    'install_hooks.rb',
    'img/Breaker.jpg'
  ]

  # Definir los hooks de instalación
  info.metadata = {
    "rubygems_mfa_required" => "true",
    "install_hooks" => "install_hooks.rb"
  }

  info.homepage    = 'https://github.com/BreakingTWS/CoBreak'
  info.license     = 'MIT'
  
  # Mensaje post-instalación actualizado
  info.post_install_message = <<-MESSAGE
Thanks for installing CoBreak!

CoBreak has been installed and will be integrated into your system menu.
If you installed without sudo privileges, please run:
    sudo gem install cobreak

For more information visit: https://github.com/BreakingTWS/CoBreak
MESSAGE

  # Cargar y ejecutar el hook de instalación
  def info.post_install
    require_relative 'install_hooks'
  end
end
