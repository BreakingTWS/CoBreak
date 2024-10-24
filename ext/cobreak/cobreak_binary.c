#include<cobreak_binary.h>
#include<cobreak_ruby.h>

VALUE cCoBreakBinary;

#define MAX_LENGTH 1024  // Definición de MAX_LENGTH

// Función para codificar un bloque de bytes en formato binario
void encodeblock_binary(const char bl[], char *blstr, size_t length) {
    for (size_t i = 0; i < length; i++) {
        for (int j = 7; j >= 0; j--) {
            blstr[i * 8 + (7 - j)] = ((bl[i] >> j) & 1) ? '1' : '0';
        }
    }
    blstr[length * 8] = '\0';  // Terminar la cadena
}

// Función para decodificar un bloque de bytes desde formato binario
void decodeblock_binary(const char bl[], char *blstr, size_t length) {
    for (size_t i = 0; i < length / 8; i++) {
        char byte = 0;
        for (int j = 0; j < 8; j++) {
            byte = (byte << 1) | (bl[i * 8 + j] - '0');
        }
        blstr[i] = byte;
    }
    blstr[length / 8] = '\0';  // Terminar la cadena
}

// Método para codificar en binario
VALUE binary_encode(VALUE self, VALUE full) {
    char *strb = RSTRING_PTR(full);
    char mybinary[MAX_LENGTH * 8 + 1];  // Buffer para la codificación
    size_t length = strlen(strb);

    // Codificación
    encodeblock_binary(strb, mybinary, length);
    return rb_str_new2(mybinary);
}

// Método para decodificar desde binario
VALUE binary_decode(VALUE self, VALUE full) {
    char *mybinary = RSTRING_PTR(full);
    char strb[MAX_LENGTH];  // Buffer para la decodificación
    size_t length = strlen(mybinary);

    // Validar longitud
    if (length % 8 != 0) {
        rb_raise(rb_eArgError, "Binary string must have a length that is a multiple of 8");
    }

    // Decodificación
    decodeblock_binary(mybinary, strb, length);
    return rb_str_new2(strb);
}

// Inicialización de la clase
void init_cobreak_binary() {
    cCoBreakBinary = rb_define_class_under(mCoBreak, "Binary", rb_cObject);
    rb_define_singleton_method(cCoBreakBinary, "encode", binary_encode, 1);
    rb_define_singleton_method(cCoBreakBinary, "decode", binary_decode, 1);
}