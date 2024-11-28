#include<cobreak_ruby.h>

VALUE mCoBreak;

void Init_cobreak(){

	mCoBreak = rb_define_module("CoBreak");






	init_cobreak_openssl();
	init_cobreak_gcrypt();
	init_cobreak_cipher();
	init_cobreak_attack_wordlist();
	init_cobreak_attack_cipherw();
}
