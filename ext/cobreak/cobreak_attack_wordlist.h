#ifndef COBREAK_ATTACK_WORDLIST_RUBY
#define COBREAK_ATTACK_WORDLIST_RUBY

//include library <cobreak_ruby.h> for project
#include<cobreak_ruby.h>

//definition body for file <header>
#include<gcrypt.h>

VALUE mCoBreakAttackWordlist;
VALUE cCoBreakAttackWordlistMD4;
VALUE cCoBreakAttackWordlistMD5;
VALUE cCoBreakAttackWordlistHALF_MD5;
VALUE cCoBreakAttackWordlistSHA1;
VALUE cCoBreakAttackWordlistDouble_SHA1;
VALUE cCoBreakAttackWordlistSHA2_224;
VALUE cCoBreakAttackWordlistSHA2_256;
VALUE cCoBreakAttackWordlistSHA2_384;
VALUE cCoBreakAttackWordlistSHA2_512;
VALUE cCoBreakAttackWordlistSHA3_224;
VALUE cCoBreakAttackWordlistSHA3_256;
VALUE cCoBreakAttackWordlistSHA3_384;
VALUE cCoBreakAttackWordlistSHA3_512;
VALUE cCoBreakAttackWordlistRipemd_160;
VALUE cCoBreakAttackWordlistTiger_160;
VALUE cCoBreakAttackWordlistBlake2s_128;
VALUE cCoBreakAttackWordlistBlake2s_160;
VALUE cCoBreakAttackWordlistBlake2b_160;
VALUE cCoBreakAttackWordlistBlake2s_224;
VALUE cCoBreakAttackWordlistBlake2s_256;
VALUE cCoBreakAttackWordlistBlake2b_256;
VALUE cCoBreakAttackWordlistBlake2b_384;
VALUE cCoBreakAttackWordlistBlake2b_512;
VALUE cCoBreakAttackWordlistWhirlpool;

//initialize function
void init_cobreak_attack_wordlist();

#endif