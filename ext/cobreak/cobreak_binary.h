#ifndef COBREAK_BINARY_RUBY
#define COBREAK_BINARY_RUBY
#include<cobreak_ruby.h>
void decodeblock_binary(const char bl[], char *blstr, size_t length);

void encodeblock_binary(const char bl[], char *blstr, size_t length);

void init_cobreak_binary();

#endif