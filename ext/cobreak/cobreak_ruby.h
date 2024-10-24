#ifndef COBREAK_RUBY
#define COBREAK_RUBY

#include<ruby.h>
#include<string.h>
#include<stdbool.h>
#include<stdlib.h>
#include<stdio.h>
#include<stdint.h>

extern VALUE mCoBreak;
#if 0
	VALUE mCoBreak = rb_define_module("CoBreak");
#endif

#include<cobreak_base64.h>
#include<cobreak_base32.h>
#include<cobreak_base16.h>
#include<cobreak_ascii85.h>
#include<cobreak_binary.h>
#include<cobreak_cesar.h>
#include<cobreak_openssl.h>
#include<cobreak_gcrypt.h>
#include<cobreak_nettle.h>
#include<cobreak_cipher.h>
//#include<cobreak_exception.h>
//continue...
#endif
