#ifndef __USE_SIGNAL_H__
#define __USE_SIGNAL_H__
#   ifndef SYS_SECCOMP
#   define SYS_SECCOMP 1
#   endif

#include <sys/ucontext.h>
#include <sys/signal.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

void SetupPassthru(void);
#endif
