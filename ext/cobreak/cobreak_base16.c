#include<cobreak_base16.h>
#include<cobreak_ruby.h>


VALUE cCoBreakBase16;

#define MAX_LENGTH 1024  // Definición de MAX_LENGTH

void decodeblock16(const char bl[], char *blstr, size_t length) {
    for (size_t i = 0; i < length / 2; i++) {
        int byte = 0;
        if (sscanf(bl + (i * 2), "%2x", &byte) != 1) {
            // Manejar error: entrada hex inválida
            rb_raise(rb_eArgError, "Invalid hex input");
            return; // Esto no se alcanzará, pero es una buena práctica
        }
        blstr[i] = (unsigned char)byte;
    }
    blstr[length / 2] = '\0';  // Terminar correctamente la cadena
}

VALUE b16_decode(VALUE self, VALUE full) {
    char *myb16 = RSTRING_PTR(full);
    char strb16[MAX_LENGTH];
    size_t length = strlen(myb16);

    // Validar longitud
    if (length % 2 != 0) {
        rb_raise(rb_eArgError, "Hex string must have an even length");
    }

    // Decodificación
    decodeblock16(myb16, strb16, length);
    return rb_str_new2(strb16);
}

void encodeblock16(const char bl[], size_t length, char b16str[]) {
    const char *hexDigits = "0123456789ABCDEF";
    for (size_t i = 0; i < length; i++) {
        b16str[i * 2] = hexDigits[(bl[i] >> 4) & 0x0F];    // Primer dígito
        b16str[i * 2 + 1] = hexDigits[bl[i] & 0x0F];       // Segundo dígito
    }
    b16str[length * 2] = '\0';  // Agregar el terminador de cadena
}

VALUE b16_encode(VALUE self, VALUE full) {
    char *strb16 = RSTRING_PTR(full);
    char myb16[MAX_LENGTH * 2 + 1];  // Buffer para la codificación
    size_t length = strlen(strb16);

    // Codificación
    encodeblock16(strb16, length, myb16);
    return rb_str_new2(myb16);
}

void init_cobreak_base16() {
    cCoBreakBase16 = rb_define_class_under(mCoBreak, "Base16", rb_cObject);
    rb_define_singleton_method(cCoBreakBase16, "encode", b16_encode, 1);
    rb_define_singleton_method(cCoBreakBase16, "decode", b16_decode, 1);
}