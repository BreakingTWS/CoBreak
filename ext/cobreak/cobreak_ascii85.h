#ifndef COBREAK_ASCII85_RUBY
#define COBREAK_ASCII85_RUBY
#include<cobreak_ruby.h>
void decodeblock85(const char bl[], char *blstr, size_t length);

void encodeblock85(const char bl[], char *blstr, size_t length);

void init_cobreak_ascii85();

#endif
