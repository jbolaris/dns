CC=gcc
all: dns

client: dns.o
	gcc -o dns dns.c

