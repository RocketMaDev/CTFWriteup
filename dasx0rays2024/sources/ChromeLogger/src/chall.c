#include "logo.h"
#include "chall.h"

#include <bits/types/stack_t.h>
#include <fcntl.h>
#include <seccomp.h>
#include <time.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef FALLBACK
static void SubmitTask(int init);
#endif

static int filtered = 1;

__attribute__((noinline))
static void init(void) {
    if (filtered) {
        SetupPassthru();
    }
#ifdef FALLBACK
    SubmitTask(1);
#endif
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("\n%s\n", LOGO);
}

__attribute__((noinline))
static int sandbox(void) {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
        return -1;

#ifdef USE_PTRACE
    int rc = seccomp_rule_add(ctx, SCMP_ACT_TRACE(0), SCMP_SYS(execve), 0);
    if (rc < 0)
        goto cleanup;
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
#else
    int rc = seccomp_rule_add(ctx, SCMP_ACT_TRAP, SCMP_SYS(execve), 0);
#endif
    if (rc < 0)
        goto cleanup;
    rc = seccomp_load(ctx);

cleanup:
    seccomp_release(ctx);
    return rc < 0 ? -1 : 0;
}

static void NewLog(void);
static void DisplayLogs(void);
static void Backdoor(int);

__attribute__((noinline))
static int getNum(void) {
    int val;
    int right = scanf("%d%*c", &val);
    if (!right) {
        while (getchar() != '\n'); 
        val = -1;
    }
    return val;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "PRIVILEGED"))
        filtered = 0;
    init();
    if (filtered)
        sandbox();
    int choice = 0;
    int mangle = 0;
    while (choice != 3) {
        printf("%s", MENU);
        choice = getNum();
        switch (choice) {
            case 1: NewLog(); break;
            case 2: DisplayLogs(); break;
            case 3: break;
            case 4: mangle = 1; break;
#ifdef FALLBACK
            case 5: SubmitTask(0); break;
#endif
            default: puts("Incorrect choice."); break;
        }
    }
    Backdoor(mangle);
    // execlp("bash", "bash", NULL);
    return 0;
}

#define LOGSIZE 32
static char *logs[LOGSIZE];
static int idx = 0;

__attribute__((noinline))
static void NewLog(void) {
    if (idx == LOGSIZE) {
        puts("Out of bounds write detected. Exiting...");
        _exit(1);
    }
    printf("Input log size:\nSIZE> ");
    int size = getNum();
    if (size < 32 || size > 512) {
        puts("Invalid size");
        return;
    }
    char *ptr = malloc(size);
    printf("Do you want to assign this chunk as a FILE buffer? [y/n]");
    char op;
    scanf("%c%*c", &op);
    if (op == 'y') {
        setvbuf(stdout, ptr, _IOFBF, 256);
        return;
    } else if (op != 'n') {
        puts("What did you mean?");
        return;
    }
    time_t now = time(NULL);
    struct tm* nowtm = localtime(&now);
    strftime(ptr, 12, "[%H:%M:%S] ", nowtm);
    printf("Now input your log:\nLOG> ");
    read(STDIN_FILENO, ptr + 11, size - 11);
    logs[idx++] = ptr;
}

__attribute__((noinline))
static void DisplayLogs(void) {
    for (int i = 0; i < idx; i++) {
        int len = strlen(logs[i]);
        if (logs[i][len - 1] != '\n') {
            len = (len + 7) & ~7;
            fwrite(logs[i], 1, len, stdout);
            putchar('\n');
        } else {
            fwrite(logs[i], 1, len, stdout);
        }
    }
}

__attribute__((noinline))
static void Backdoor(int mangle) {
    if (!mangle)
        return;
    printf("You have one chance to mangle a log\nINDEX> ");
    unsigned int i = getNum();
    if (i >= (unsigned int)idx) {
        puts("No such log");
        _exit(2);
    }
    PTR_MANGLE((long *)(logs[i] + 0x80));
    puts("Log mangled, good luck!");
}

#ifdef FALLBACK
__attribute__((noinline))
static void SubmitTask(int init) {
    static size_t heapBase, heapEnd;
    if (init)
        goto fetchbase;
checkheap:
    puts("You may need a heap base.");
    printf("Input a leaked heap addr in hex:\nHEAP> ");
    size_t addr;
    int valid = scanf("%lx", &addr);
    if (!valid) {
invalid:
        puts("Input a right value!");
        exit(4);
    }
    if (addr > heapBase && addr < heapEnd) {
        printf("Correct! Here you are: %p\n", (void *)heapBase);
        return;
    } else 
        goto invalid;
fetchbase:
    heapBase = heapEnd = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    char buf[256];
    char *neof;
    buf[255] = 0;
    do {
        neof = fgets(buf, 255, maps);
        if (strstr(buf, "heap"))
            break;
    } while (neof);
    sscanf(buf, "%lx-%lx", &heapBase, &heapEnd);
    fclose(maps);
}
#endif
