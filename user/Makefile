CC = gcc
DIR1 = ../lib
SRC = app.c $(DIR1)/flexsc.h $(DIR1)/flexsc.c

all: app

%.o: %.c
	$(CC) -c -o $@ $<

app:
	$(CC) $(SRC) -pthread -g -D_GNU_SOURCE -o app

.PHONY: clean app
clean:
	rm -f *.o app test
