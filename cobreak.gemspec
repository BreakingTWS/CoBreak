Gem::Specification.new do |info|
  info.name        = 'cobreak'
  info.version     = '1.0.5'
  info.executables << "cobreak" 
  info.executables << "cbrdb"
  info.description = "The CoBreak script is an cipher and cryptography tool"
  info.add_development_dependency "bundler", "~> 2.3"
  info.add_development_dependency  "sequel", "~> 5.44.0"
  info.add_development_dependency  "sqlite3", '~> 1.4', '>= 1.4.0'
  info.add_runtime_dependency "sqlite3", '~> 1.4', '>= 1.4.0'
  info.add_runtime_dependency "gtk3", '~> 3.4'
  info.add_runtime_dependency "ruby_figlet"
  info.authors     = ["BreakerTW"]
  info.email       = 'breakingtws@gmail.com'
  info.summary     = "Force Brute, Cipher, Cryptography"

  info.extensions = %w[ext/cobreak/extconf.rb]

  info.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(/^.gitignore/)
  end

  info.homepage    = 'https://github.com/BreakingTWS/CoBreak'
  info.license       = 'MIT'
  info.post_install_message = "thanks for installing my gem"
end
