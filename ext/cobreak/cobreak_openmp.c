#include "cobreak_ruby.h"
#include<cobreak_openmp.h>

VALUE mCoBreakOpenMP;

void init_cobreak_openmp(){

    mCoBreakOpenMP = rb_define_module_under(mCoBreak, "OpenMP");
}