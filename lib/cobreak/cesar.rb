class CesarCifrado
  def cesar(dato, rotasiones, orientacion = 1)
    cesar = OpenStruct.new
    cesar.cad_rot = []
    alfa_mayus = ('A'..'Z').to_a
    alfa_minus = ('a'..'z').to_a
    alf = 26
    lit_mayus = 65
    lit_minus = 97
    cad_rot = ""
    for letra in dato.chars
      if !letra.match(/^[[:alpha:]]$/)
        cad_rot += letra
        next
      end
      alfabeto = alfa_mayus
      limit = lit_mayus
      if letra == letra.downcase
        alfabeto = alfa_minus
        limit = lit_minus
      end
      var_ascii = letra.ord
      rot_ver = rotasiones * orientacion
      new_pos = (var_ascii - limit + rot_ver) % alf
      cesar.cad_rot << alfabeto[new_pos]
      end
      return cesar.cad_rot.join('')
  end
end
Cesar = CesarCifrado.new