#include<cobreak_cipher.h>

VALUE mCoBreakCipher;
VALUE cCoBreakBase16;
VALUE cCoBreakBase32;
VALUE cCoBreakBase64;
VALUE cCoBreakCesar;
VALUE cCoBreakBinary;
VALUE cCoBreakVigenere;

char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//Base16
void decodeblock16(const char bl[], char *blstr, size_t length) {
    for (size_t i = 0; i < length / 2; i++) {
        int byte = 0;
        if (sscanf(bl + (i * 2), "%2x", &byte) != 1) {
            rb_raise(rb_eArgError, "Invalid hex input");
            return; 
        }
        blstr[i] = (unsigned char)byte;
    }
    blstr[length / 2] = '\0';
}

VALUE b16_decode(VALUE self, VALUE full) {
    char *myb16 = RSTRING_PTR(full);
    char strb16[1024];
    size_t length = strlen(myb16);

    if (length % 2 != 0) {
        rb_raise(rb_eArgError, "Hex string must have an even length");
    }

    decodeblock16(myb16, strb16, length);
    return rb_str_new2(strb16);
}

void encodeblock16(const char bl[], size_t length, char b16str[]) {
    const char *hexDigits = "0123456789ABCDEF";
    for (size_t i = 0; i < length; i++) {
        b16str[i * 2] = hexDigits[(bl[i] >> 4) & 0x0F];
        b16str[i * 2 + 1] = hexDigits[bl[i] & 0x0F];      
    }
    b16str[length * 2] = '\0';
}

VALUE b16_encode(VALUE self, VALUE full) {
    char *strb16 = RSTRING_PTR(full);
    char myb16[1024 * 2 + 1]; 
    size_t length = strlen(strb16);

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
            break; 
        }

        int value = strchr(b32, bl[i]) - b32;
        if (value < 0 || value >= 32) {
            break;
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

    
    int decoded_length = decodeblock32(myb32, clrdst);
    clrdst[decoded_length] = '\0'; 

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


//Base64
void decodeblock64(unsigned char in[], char *clrstr) {
	unsigned char out[4];
	out[0] = in[0] << 2 | in[1] >> 4;
	out[1] = in[1] << 4 | in[2] >> 2;
	out[2] = in[2] << 6 | in[3] >> 0;
	out[3] = '\0';
	strncat(clrstr, out, sizeof(out));
}

VALUE b64_decode(VALUE self, VALUE full){
	int c, phase, i;
	unsigned char in[4];
	char *p;

	char *myb64 = RSTRING_PTR(full);
	char strb64[1024] = "";
	char *clrdst = strb64;
	clrdst[0] = '\0';
	phase = 0; i=0;
	while(myb64[i]){
		c = (int) myb64[i];
		if(c == '='){
			decodeblock64(in, clrdst);
			break;
		}
		p = strchr(b64, c);
		if(p){
			in[phase] = p - b64;
			phase = (phase + 1) % 4;
			if(phase == 0){
				decodeblock64(in, clrdst);
				in[0]=in[1]=in[2]=in[3]=0;
			}
		}
		i++;
	}
	return rb_str_new2(strb64);
}

void encodeblock64(unsigned char bl[], char b64str[], int len){
	unsigned char out[5];
	out[0] = b64[ bl[0] >> 2 ];
	out[1] = b64[ ((bl[0] & 0x03) << 4) | ((bl[1] & 0xf0) >> 4) ];
	out[2] = (unsigned char) (len > 1 ? b64[ ((bl[1] & 0x0f) << 2) | ((bl[2] & 0xc0) >> 6) ] : '=');
	out[3] = (unsigned char) (len > 2 ? b64[ bl[2] & 0x3f ] : '=');
	out[4] = '\0';
	strncat(b64str, out, sizeof(out));
}

VALUE b64_encode(VALUE self, VALUE full){
	unsigned char in[3];
	int i, len = 0;
	int j = 0;
	char *strb64 = RSTRING_PTR(full);
	char myb64[1024] = "";
	char *b64dst = myb64;
	b64dst[0] = '\0';
	while(strb64[j]){
		len = 0;
		for(i=0; i<3; i++){
			in[i] = (unsigned char) strb64[j];
			if(strb64[j]) {
				len++; j++;
			}
			else in[i] = 0;
		}
		if(len){
			encodeblock64(in, b64dst, len);
		}
	}
	return rb_str_new2(b64dst);
}

//Define Cesar
void encodeblock_cesar(const char *input, char *output, int shift){
    for (size_t i = 0; i < strlen(input); i++) {
        char c = input[i];

        if (c >= 'A' && c <= 'Z') {
            output[i] = (c - 'A' + shift) % 26 + 'A';
        } else if (c >= 'a' && c <= 'z') {
            output[i] = (c - 'a' + shift) % 26 + 'a';
        } else {
            output[i] = c;
        }
    }
    output[strlen(input)] = '\0';
}


void decodeblock_cesar(const char *input, char *output, int shift){
    
    encodeblock_cesar(input, output, 26 - (shift % 26));
}

VALUE cesar_encode(VALUE self, VALUE str, VALUE shift) {
    char *input = RSTRING_PTR(str);
    char output[1024];  // Buffer para la salida
    int shift_value = NUM2INT(shift);

   
    encodeblock_cesar(input, output, shift_value);
    return rb_str_new2(output);
}


VALUE cesar_decode(VALUE self, VALUE str, VALUE shift) {
    char *input = RSTRING_PTR(str);
    char output[1024];  // Buffer para la salida
    int shift_value = NUM2INT(shift);

   
    decodeblock_cesar(input, output, shift_value);
    return rb_str_new2(output);
}

//Define Binary
void encodeblock_binary(const char bl[], char *blstr, size_t length) {
    for (size_t i = 0; i < length; i++) {
        for (int j = 7; j >= 0; j--) {
            blstr[i * 8 + (7 - j)] = ((bl[i] >> j) & 1) ? '1' : '0';
        }
    }
    blstr[length * 8] = '\0';  
}

void decodeblock_binary(const char bl[], char *blstr, size_t length) {
    for (size_t i = 0; i < length / 8; i++) {
        char byte = 0;
        for (int j = 0; j < 8; j++) {
            byte = (byte << 1) | (bl[i * 8 + j] - '0');
        }
        blstr[i] = byte;
    }
    blstr[length / 8] = '\0'; 
}

VALUE binary_encode(VALUE self, VALUE full) {
    char *strb = RSTRING_PTR(full);
    char mybinary[1024 * 8 + 1]; 
    size_t length = strlen(strb);

    encodeblock_binary(strb, mybinary, length);
    return rb_str_new2(mybinary);
}


VALUE binary_decode(VALUE self, VALUE full) {
    char *mybinary = RSTRING_PTR(full);
    char strb[1024];
    size_t length = strlen(mybinary);

    if (length % 8 != 0) {
        rb_raise(rb_eArgError, "Binary string must have a length that is a multiple of 8");
    }

    decodeblock_binary(mybinary, strb, length);
    return rb_str_new2(strb);
}

void vigenere_encode_block(const char *input, const char *key, char *output) {
    size_t input_len = strlen(input);
    size_t key_len = strlen(key);
    
    for (size_t i = 0, j = 0; i < input_len; i++) {
        char c = input[i];

        if (c >= 'A' && c <= 'Z') {
            output[i] = (c - 'A' + (key[j % key_len] - 'A')) % 26 + 'A';
            j++;
        } else if (c >= 'a' && c <= 'z') {
            output[i] = (c - 'a' + (key[j % key_len] - 'a')) % 26 + 'a';
            j++;
        } else {
            output[i] = c;
        }
    }
    output[input_len] = '\0';
}

VALUE vigenere_encode(VALUE self, VALUE str, VALUE key) {
    char *input = RSTRING_PTR(str);
    char *key_str = RSTRING_PTR(key);
    char output[1024];

    vigenere_encode_block(input, key_str, output);
    return rb_str_new2(output);
}

void vigenere_decode_block(const char *input, const char *key, char *output) {
    size_t input_len = strlen(input);
    size_t key_len = strlen(key);
    
    for (size_t i = 0, j = 0; i < input_len; i++) {
        char c = input[i];

        if (c >= 'A' && c <= 'Z') {
            output[i] = (c - 'A' - (key[j % key_len] - 'A') + 26) % 26 + 'A';
            j++;
        } else if (c >= 'a' && c <= 'z') {
            output[i] = (c - 'a' - (key[j % key_len] - 'a') + 26) % 26 + 'a';
            j++;
        } else {
            output[i] = c;
        }
    }
    output[input_len] = '\0';
}

VALUE vigenere_decode(VALUE self, VALUE str, VALUE key) {
    char *input = RSTRING_PTR(str);
    char *key_str = RSTRING_PTR(key);
    char output[1024];

    vigenere_decode_block(input, key_str, output);
    return rb_str_new2(output);
}

// SVG Encoding
VALUE svg_encode(VALUE self, VALUE full) {
    char *svg_content = RSTRING_PTR(full);
    VALUE encoded_value = b64_encode(self, full); // Use existing base64 encode
    return encoded_value;
}

VALUE svg_decode(VALUE self, VALUE full) {
    VALUE decoded_value = b64_decode(self, full); // Use existing base64 decode
    return decoded_value;
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

    //Define class Base64 in module mCoBreakCipher
    cCoBreakBase64 = rb_define_class_under(mCoBreakCipher, "Base64", rb_cObject);

    //Define method for class Base64
    rb_define_singleton_method(cCoBreakBase64, "encode", b64_encode, 1);
    rb_define_singleton_method(cCoBreakBase64, "decode", b64_decode, 1);
    //Define method for class Base16
    rb_define_singleton_method(cCoBreakBase16, "svg_encode", svg_encode, 1);
    rb_define_singleton_method(cCoBreakBase16, "svg_decode", svg_decode, 1);


    //Define class Cesar in module mCoBreakCipher
    cCoBreakCesar = rb_define_class_under(mCoBreakCipher, "Cesar", rb_cObject);

    //Define method for class Cesar
    rb_define_singleton_method(cCoBreakCesar, "encode", cesar_encode, 2);
    rb_define_singleton_method(cCoBreakCesar, "decode", cesar_decode, 2);

    //Define class Cesar in module mCoBreakCipher
    cCoBreakBinary = rb_define_class_under(mCoBreakCipher, "Binary", rb_cObject);

    //Define method for class Binary
    rb_define_singleton_method(cCoBreakBinary, "encode", binary_encode, 1);
    rb_define_singleton_method(cCoBreakBinary, "decode", binary_decode, 1);

    //Define class Vigenere in module mCoBreakCipher
    cCoBreakVigenere = rb_define_class_under(mCoBreakCipher, "Vigenere", rb_cObject);

    //Define method for class Binary
    rb_define_singleton_method(cCoBreakVigenere, "encode", vigenere_encode, 2);
    rb_define_singleton_method(cCoBreakVigenere, "decode", vigenere_decode, 2);
}
