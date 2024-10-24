#ifndef COBREAK_BASE32_RUBY
#define COBREAK_BASE32_RUBY
#include<cobreak_ruby.h>
int decodeblock32(const char bl[], char *blstr);

void encodeblock32(const char bl[], int len, char b32str[]);

void init_cobreak_base32();

#endif
