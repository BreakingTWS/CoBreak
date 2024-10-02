#include<cobreak_ruby.h>

VALUE mCoBreak;

void Init_cobreak(){

	mCoBreak = rb_define_module("CoBreak");




	init_cobreak_base64();
	init_cobreak_openssl();
}
