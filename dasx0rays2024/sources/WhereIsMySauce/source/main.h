#ifndef __SAUCE_MAIN_H__
#define __SAUCE_MAIN_H__
#include <stdio.h>
#include <stdbool.h>

typedef void (*FUNCPTR)(void);
#define DISH_CNT 10
extern const char *dishes[];
#define GREEN_TXT "\x1b[32m"
#define DEFAULT_TXT "\x1b[0m"

void regfunc(FUNCPTR);

#endif // __SAUCE_MAIN_H__
