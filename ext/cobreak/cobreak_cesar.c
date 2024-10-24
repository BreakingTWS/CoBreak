#include<cobreak_cesar.h>
#include<cobreak_ruby.h>


VALUE cCoBreakCesar;

#define MAX_LENGTH 1024  // Definición de MAX_LENGTH

// Función para cifrar una cadena usando la cifra de César
void encodeblock_cesar(const char *input, char *output, int shift){
    for (size_t i = 0; i < strlen(input); i++) {
        char c = input[i];

        // Cifrar solo letras mayúsculas y minúsculas
        if (c >= 'A' && c <= 'Z') {
            output[i] = (c - 'A' + shift) % 26 + 'A';
        } else if (c >= 'a' && c <= 'z') {
            output[i] = (c - 'a' + shift) % 26 + 'a';
        } else {
            output[i] = c;  // No cifrar otros caracteres
        }
    }
    output[strlen(input)] = '\0';  // Terminar la cadena
}

// Función para descifrar una cadena usando la cifra de César
void decodeblock_cesar(const char *input, char *output, int shift){
    // Para descifrar, se usa el desplazamiento negativo
    encodeblock_cesar(input, output, 26 - (shift % 26));
}

// Método para cifrar en César
VALUE cesar_encode_wrapper(VALUE self, VALUE str, VALUE shift) {
    char *input = RSTRING_PTR(str);
    char output[MAX_LENGTH];  // Buffer para la salida
    int shift_value = NUM2INT(shift);

    // Cifrado
    encodeblock_cesar(input, output, shift_value);
    return rb_str_new2(output);
}

// Método para descifrar en César
VALUE cesar_decode_wrapper(VALUE self, VALUE str, VALUE shift) {
    char *input = RSTRING_PTR(str);
    char output[MAX_LENGTH];  // Buffer para la salida
    int shift_value = NUM2INT(shift);

    // Descifrado
    decodeblock_cesar(input, output, shift_value);
    return rb_str_new2(output);
}

// Inicialización de la clase
void init_cobreak_cesar() {
    cCoBreakCesar = rb_define_class_under(mCoBreak, "Cesar", rb_cObject);
    rb_define_singleton_method(cCoBreakCesar, "encode", cesar_encode_wrapper, 2);
    rb_define_singleton_method(cCoBreakCesar, "decode", cesar_decode_wrapper, 2);
}