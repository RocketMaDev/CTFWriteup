#ifndef __CHALL_H__
#define __CHALL_H__
#ifdef USE_PTRACE
#   include "use_ptrace.h"
#else
#   include "use_signal.h"
#endif
extern void PTR_MANGLE(long *); // from mangle.s
#endif
