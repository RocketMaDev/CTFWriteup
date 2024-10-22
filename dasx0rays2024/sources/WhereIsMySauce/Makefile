CC=gcc
CFLAGS=-Wall -Wextra -O3 -g
SRC_DIR=/usr/src/sauce
SRCS=$(wildcard $(SRC_DIR)/*.c)
OBJS=$(SRCS:.c=.o)
TARGET=cook

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
