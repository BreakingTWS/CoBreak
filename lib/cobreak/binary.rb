module CoBreak
  class Binary
    def self.binary(dato)
      return dato.unpack("B*").join('')
    end
    def self.hexbinary(dato)
      return [dato].pack("B*")
    end
  end
end
