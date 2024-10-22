#ifndef __USE_PTRACE_H__
#define __USE_PTRACE_H__

#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void SetupPassthru(void);
#endif
