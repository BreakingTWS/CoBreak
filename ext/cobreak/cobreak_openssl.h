#ifndef COBREAK_OPENSSL_RUBY
#define COBREAK_OPENSS_RUBY

//include library <cobreak_ruby.h> for project
#include<cobreak_ruby.h>

//definition body for file <header>
#include<openssl/sha.h>
//#include<openssl/sha3.h>
#include<openssl/md4.h>
#include<openssl/md5.h>
#include<openssl/ripemd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
//#include<crypto.h>
//#include<ssl.h>

//initialize function
void init_cobreak_openssl();

#endif
