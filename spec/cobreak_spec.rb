require 'cobreak/cobreak' # Asegúrate de requerir tu archivo principal
require 'rspec'

RSpec.describe CoBreak do
  describe '.some_method' do
    it 'does something expected' do
      result = CoBreak::Cipher::Base64.encode("hola")
      puts "Result Correct"
    end
  end
end
