#include<cobreak_ruby.h>

VALUE mCoBreak;

void Init_cobreak(){

	mCoBreak = rb_define_module("CoBreak");




	init_cobreak_base64();
	init_cobreak_base32();
	init_cobreak_base16();
	init_cobreak_ascii85();
	init_cobreak_binary();
	init_cobreak_cesar();
	init_cobreak_openssl();
	init_cobreak_gcrypt();
	init_cobreak_cipher();
}
