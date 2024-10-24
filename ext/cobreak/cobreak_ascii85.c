#include<cobreak_ascii85.h>
#include<cobreak_ruby.h>


VALUE cCoBreakASCII85;

#define MAX_LENGTH 1024  // Definición de MAX_LENGTH

// Función para codificar un bloque de bytes en ASCII85
void encodeblock85(const char bl[], char *blstr, size_t length) {
    unsigned long val = 0;
    int count = 0;
    char *dst = blstr;

    for (size_t i = 0; i < length; i++) {
        val = (val << 8) | (unsigned char)bl[i];
        count += 8;
        while (count >= 32) {
            *dst++ = '!' + (val >> 24);
            val <<= 8;
            count -= 32;
        }
    }
    if (count > 0) {
        val <<= (32 - count);
        *dst++ = '!' + (val >> 24);
    }
    *dst = '\0';  // Terminar la cadena
}

// Función para decodificar un bloque de bytes desde ASCII85
void decodeblock85(const char bl[], char *blstr, size_t length) {
    unsigned long val = 0;
    int count = 0;
    char *dst = blstr;

    for (size_t i = 0; i < length; i++) {
        if (bl[i] < '!' || bl[i] > 'u') {
            // Manejar error: carácter inválido
            rb_raise(rb_eArgError, "Invalid ASCII85 input");
            return;
        }
        val = (val << 8) | (bl[i] - '!');
        count += 8;
        while (count >= 32) {
            *dst++ = (val >> 24) & 0xFF;
            val <<= 8;
            count -= 32;
        }
    }
    if (count > 0) {
        val <<= (32 - count);
        *dst++ = (val >> 24) & 0xFF;
    }
    *dst = '\0';  // Terminar la cadena
}

// Método para codificar en ASCII85
VALUE ascii85_encode(VALUE self, VALUE full) {
    char *strb85 = RSTRING_PTR(full);
    char myb85[MAX_LENGTH * 5 + 1];  // Buffer para la codificación
    size_t length = strlen(strb85);

    // Codificación
    encodeblock85(strb85, myb85, length);
    return rb_str_new2(myb85);
}

// Método para decodificar desde ASCII85
VALUE ascii85_decode(VALUE self, VALUE full) {
    char *myb85 = RSTRING_PTR(full);
    char strb85[MAX_LENGTH];  // Buffer para la decodificación
    size_t length = strlen(myb85);

    // Decodificación
    decodeblock85(myb85, strb85, length);
    return rb_str_new2(strb85);
}

// Inicialización de la clase
void init_cobreak_ascii85() {
    cCoBreakASCII85 = rb_define_class_under(mCoBreak, "Ascii85", rb_cObject);
    rb_define_singleton_method(cCoBreakASCII85, "encode", ascii85_encode, 1);
    rb_define_singleton_method(cCoBreakASCII85, "decode", ascii85_decode, 1);
}