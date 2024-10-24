require 'optparse'
module CoBreakOPT
  class Runner
    def self.runner(options)
      require 'cobreak/optionpr'
      CoBreak::ParseOPT.optparse(options)
    end
  end
end
