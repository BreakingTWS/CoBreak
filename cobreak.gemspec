Gem::Specification.new do |info|
  info.name        = 'cobreak'
  info.version     = '1.0.5'
  info.executables << "cobreak" 
  info.executables << "cbrdb"
  info.description = "The CoBreak script is an cipher and cryptography tool"
  info.add_development_dependency "bundler", "~> 1.5"
  info.add_development_dependency  "openssl", "~> 2.2.0"
  info.add_development_dependency  "sequel", "~> 5.44.0"
  info.add_development_dependency  "sqlite3", '~> 1.4', '>= 1.4.0'
#  info.add_runtime_dependency "sequel", '~> 2.0', '>= 2.0.0'
  info.add_runtime_dependency "sqlite3", '~> 1.4', '>= 1.4.0'
  info.add_runtime_dependency "Ascii85", '~> 1.0', '>= 1.0.0'
#  info.add_runtime_dependency "ruby_figlet", "=> 0"
  info.authors     = ["BreakerTW"]
  info.email       = 'breaker@gmail.com'
  info.summary     = "Force Brute, Cipher, Cryptography"

  info.extensions = %w[ext/cobreak/extconf.rb]

  info.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(/^.gitignore/)
  end

  info.homepage    = 'https://github.com/BreakerBox/CoBreak'
  info.license       = 'MIT'
  info.post_install_message = "thanks for installing my gem"
end
