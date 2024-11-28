require "cobreak/cobreak" # Asegúrate de requerir tu archivo principal
require 'rspec'

RSpec.describe CoBreak do
  describe '.some_method' do
    it 'does something expected' do
      result = CoBreak::CipherAttack::Cesar.crack("hola", "rotes.txt")
      puts result
      puts "Result Correct"
    end
  end
end
