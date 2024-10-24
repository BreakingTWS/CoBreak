#include<cobreak_cipher.h>

VALUE mCoBreakCipher;
VALUE cCoBreakBase16;
VALUE cCoBreakBase32;

#define MAX_LENGTH 1024

char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//Base16
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

//Base32
int decodeblock32(const char bl[], char *blstr){
    int buffer = 0;
    int bits_left = 0;
    size_t output_length = 0;

    for (size_t i = 0; i < strlen(bl); i++) {
        if (bl[i] == '=') {
            break; // Fin del mensaje
        }

        int value = strchr(b32, bl[i]) - b32;
        if (value < 0 || value >= 32) {
            break; // Carácter inválido
        }

        buffer = (buffer << 5) | value;
        bits_left += 5;

        if (bits_left >= 8) {
            blstr[output_length++] = (buffer >> (bits_left - 8)) & 0xFF;
            bits_left -= 8;
        }
    }
    return output_length;
}

VALUE b32_decode(VALUE self, VALUE full) {
    char *myb32 = RSTRING_PTR(full);
    char strb32[1024] = "";
    char *clrdst = strb32;

    // Decodificar
    int decoded_length = decodeblock32(myb32, clrdst);
    clrdst[decoded_length] = '\0'; // Asegurar que la cadena esté terminada

    return rb_str_new2(strb32);
}


void encodeblock32(const char bl[], int len, char b32str[]){
    int buffer = 0;
    int bits_left = 0;
    size_t output_length = 0;

    for (size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | bl[i];
        bits_left += 8;

        while (bits_left >= 5) {
            b32str[output_length++] = b32[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }

    if (bits_left > 0) {
        b32str[output_length++] = b32[(buffer << (5 - bits_left)) & 0x1F];
    }

    // Añadir padding
    while (output_length % 8 != 0) {
        b32str[output_length++] = '=';
    }

    b32str[output_length] = '\0';
}

VALUE b32_encode(VALUE self, VALUE full) {
    char *strb32 = RSTRING_PTR(full);
    char myb32[1024] = "";
    char *clrdst = myb32;

   encodeblock32(strb32, strlen(strb32), clrdst);

    return rb_str_new2(myb32);
}


void init_cobreak_cipher() {
    //Define module Cipher in mCoBreak
    mCoBreakCipher = rb_define_module_under(mCoBreak, "Cipher");

    //Define class Base16 in module mCoBreakCipher
    cCoBreakBase16 = rb_define_class_under(mCoBreakCipher, "Base16", rb_cObject);

    //Define method for class Base16
    rb_define_singleton_method(cCoBreakBase16, "encode", b16_encode, 1);
    rb_define_singleton_method(cCoBreakBase16, "decode", b16_decode, 1);

    //Define class Base32 in module mCoBreakCipher
    cCoBreakBase32 = rb_define_class_under(mCoBreakCipher, "Base32", rb_cObject);

    //Define method for class Base32
    rb_define_singleton_method(cCoBreakBase32, "encode", b32_encode, 1);
    rb_define_singleton_method(cCoBreakBase32, "decode", b32_decode, 1);
}
