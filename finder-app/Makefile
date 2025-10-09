# Usage:
#   make                       # native build (gcc)
#   make clean                 # remove writer and *.o
#   make CROSS_COMPILE=aarch64-none-linux-gnu-   # cross-build

# If CROSS_COMPILE is set with aarch64-none-linux-gnu-, CC becomes that triplet + gcc
CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)gcc

CFLAGS  ?= -Wall -Wextra -Werror -O2 -g
LDFLAGS ?=
LDLIBS  ?=

TARGET := writer
SRCS   := writer.c
OBJS   := $(SRCS:.c=.o)

# Default target
.DEFAULT_GOAL := $(TARGET)

# Build the app
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Compile .c -> .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: all clean
all: $(TARGET)

clean:
	$(RM) -f $(TARGET) $(OBJS)
