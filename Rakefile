require 'bundler/gem_tasks'
require 'rake/extensiontask'

Rake::ExtensionTask.new('cobreak') do |ext|
  ext.name = 'cobreak'
  ext.ext_dir = 'ext/cobreak'
  ext.lib_dir = 'lib/cobreak'
  ext.tmp_dir = 'tmp'
  ext.source_pattern = "*.{c,h}"
end

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec)

task default: [:compile, :spec]

desc "Compile extensions and run tests"
task :dev => [:clean, :compile] do
  puts "Extensions compiled successfully!"
end
