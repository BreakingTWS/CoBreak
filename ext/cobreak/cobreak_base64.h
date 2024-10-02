#ifndef COBREAK_BASE64_RUBY
#define COBREAK_BASE64_RUBY
#include<cobreak_ruby.h>
void decodeblock(unsigned char bl[], char *blstr);

void encodeblock(unsigned char bl[], char b64str[], int len);

void init_cobreak_base64();

#endif
