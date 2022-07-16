all: client server

client: client.o crypto.o util.o
		g++ -Wall client.o -o client -lcrypto -lstdc++fs

server: server.o crypto.o util.o
		g++ -Wall server.o -o server -lcrypto -pthread -lstdc++fs

clean:
		rm *.o client server