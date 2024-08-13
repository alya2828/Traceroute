CC = gcc
CFLAGS = -Wall -Wextra

all: traceroute1

myprogram: traceroute1.c
	$(CC) $(CFLAGS) -o traceroute1 traceroute1.c

clean:
	rm -f traceroute1 