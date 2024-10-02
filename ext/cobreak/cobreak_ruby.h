#ifndef COBREAK_RUBY
#define COBREAK_RUBY

#include<ruby.h>
#include<string.h>
#include<stdbool.h>
#include<stdlib.h>
#include<stdio.h>

extern VALUE mCoBreak;
#if 0
	VALUE mCoBreak = rb_define_module("CoBreak");
#endif

#include<cobreak_base64.h>
#include<cobreak_openssl.h>
#include<cobreak_nettle.h>
//#include<cobreak_exception.h>
//continue...
#endif
