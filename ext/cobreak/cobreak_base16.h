#ifndef COBREAK_BASE16_RUBY
#define COBREAK_BASE16_RUBY
#include<cobreak_ruby.h>
void decodeblock16(const char bl[], char *blstr, size_t length);

void encodeblock16(const char bl[], size_t length, char b16str[]);

void init_cobreak_base16();

#endif
