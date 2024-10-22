CC = gcc
CFLAGS = -Wall -Wextra -O2
ASFLAGS = 
LDFLAGS = -lseccomp -ltcmalloc -fstack-protector -fPIE -z now -z noexecstack

TARGET = ChromeLogger
SRC_DIR = src
SRCS = $(wildcard $(SRC_DIR)/*.c)
ASMS = $(SRC_DIR)/mangle.s
OBJS = $(SRCS:.c=.o) $(ASMS:.s=.o)

ifdef DEBUG
	CFLAGS += -g
	ASFLAGS += -g
endif

ifdef USE_PTRACE
	CFLAGS += -DUSE_PTRACE
endif

ifdef FALLBACK
	CFLAGS += -DFALLBACK
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)
	rm $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.s
	$(CC) $(ASFLAGS) -c $< -o $@

clean:
	rm $(TARGET)

# used to copy libs out from container
ldd:
	ldd $(TARGET) | awk '{print $$3}' | xargs echo

# used to patch exe with or without debuginfo natively
patchelf:
	patchelf $(TARGET).g --add-needed libunwind.so.8
	patchelf $(TARGET).g --add-needed libstdc++.so.6
	patchelf $(TARGET).g --add-needed libm.so.6
	patchelf $(TARGET).g --add-needed libgcc_s.so.1
	patchelf $(TARGET).g --add-needed liblzma.so.5
	patchit ~/glibc-all-in-one/libs/2.39-0ubuntu8.3_amd64 $(TARGET).g
	patchelf $(TARGET).xg --add-needed libunwind.so.8
	patchelf $(TARGET).xg --add-needed libstdc++.so.6
	patchelf $(TARGET).xg --add-needed libm.so.6
	patchelf $(TARGET).xg --add-needed libgcc_s.so.1
	patchelf $(TARGET).xg --add-needed liblzma.so.5
	patchit ~/glibc-all-in-one/libs/2.39-0ubuntu8.3_amd64 $(TARGET).xg
