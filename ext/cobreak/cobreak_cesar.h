#ifndef COBREAK_CESAR_RUBY
#define COBREAK_CESAR_RUBY
#include<cobreak_ruby.h>
void decodeblock_cesar(const char *input, char *output, int shift);

void encodeblock_cesar(const char *input, char *output, int shift);

void init_cobreak_cesar();

#endif