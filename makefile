all: client server

client: client.o crypto.o util.o
		gcc -Wall client.o -o client -lcrypto

server: server.o crypto.o util.o
		gcc -Wall server.o -o server -lcrypto -pthread

clean:
		rm *.o client server