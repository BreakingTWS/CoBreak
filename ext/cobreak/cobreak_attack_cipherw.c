#include<cobreak_ruby.h>

VALUE mCoBreakAttackCipher;
VALUE cCoBreakAttackCipherCesar;

//Define Attack Cesar
void encodeblock_attack_cesar(const char *input, char *output, int shift){
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

void decodeblock_attack_cesar(const char *input, char *output, int shift){
    
    encodeblock_attack_cesar(input, output, 26 - (shift % 26));
}

VALUE cesar_attack(VALUE self, VALUE str, VALUE shift) {
    char *input = RSTRING_PTR(str);
    char output[1024];  // Buffer para la salida
    int shift_value = NUM2INT(shift);

   
    decodeblock_attack_cesar(input, output, shift_value);
    return rb_str_new2(output);
}

int cobreak_attack_cipherw(){
    //Define module Cipher in mCoBreak
    mCoBreakAttackCipher = rb_define_module_under(mCoBreak, "CipherAttack");

    //Define class Cesar attack
    cCoBreakAttackCipherCesar = rb_define_class_under(mCoBreakAttackCipher, "Cesar", rb_rObject);

    //Define method for class Cesar
    rb_define_singleton_method(cCoBreakAttackCipherCesar, "crack", cesar_attack, 2);
}
