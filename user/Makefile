CC = gcc
OBJS = test.o
all: test
%.o: %.c
	$(CC) -c -o $@ $<

test: $(OBJS)
	$(CC) -o $@ $^