#include<cobreak_base32.h>
#include<cobreak_ruby.h>

char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

VALUE cCoBreakBase32;

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

void init_cobreak_base32(){
	cCoBreakBase32 = rb_define_class_under(mCoBreak, "Base32", rb_cObject);

	rb_define_singleton_method(cCoBreakBase32, "encode", b32_encode, 1);
	rb_define_singleton_method(cCoBreakBase32, "decode", b32_decode, 1);
}
