
CC=gcc
CFLAGS=-Wall -Wextra -O2 -g $(shell pkg-config --cflags mbedtls)
LDLIBS=$(shell pkg-config --libs mbedcrypto mbedx509 mbedtls)

OBJS=tls_utils.o proto.o

all: server client

server: server.o $(OBJS)
	$(CC) -o $@ $^ $(LDLIBS)

client: client.o $(OBJS)
	$(CC) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o server client
