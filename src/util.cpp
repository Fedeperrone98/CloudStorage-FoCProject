#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

using namespace std;

void sumControl(int a, int b){
    if (a > INT_MAX - b){
        perror("integer overflow");
        exit(1);
    }   
}

void subControl(int a, int b){
	if(a <0 || b<0){
		perror("integer overflow");
		exit(-1);
	}

	if (b>a){
		perror("integer overflow");
		exit(-1);
	}
}

void IncControl(int a){
	if (a==INT_MAX){
		perror("integer overflow");
		exit(-1);
	}
}

void send_obj (int sock, unsigned char* buf, size_t len){		
//Send the message via socket
	uint32_t dim_obj = htonl(len);
	ssize_t no_err;
	
	//send object
	no_err = send(sock,(void*)buf,len, 0 );
	if(no_err == -1){
		perror("send");	
		exit(-1);
	}
}

void receive_obj (int socket_com, unsigned char* buf, int dim_buf){
//Receive the message via socket
	ssize_t no_err = recv(socket_com, buf, dim_buf, MSG_WAITALL);
	
	if (no_err < dim_buf || no_err == -1){
		perror("recv");
		exit(-1);		
	}
}

void send_int(int sock, size_t len){
	uint32_t dim_obj = htonl(len);
	ssize_t no_err;
	//send the message length first
	no_err = send (sock, &dim_obj, sizeof(uint32_t), 0);		
	if(no_err == -1 || no_err < sizeof(uint32_t)){
		perror("send lunghezza dell'oggetto");	
		exit(-1);
	}
}

int receive_len (int socket_com){
//Receive the length of the message via socket
	ssize_t no_err;
	uint32_t dim_network;
	no_err = recv(socket_com, &dim_network, sizeof(uint32_t), MSG_WAITALL);
	if (no_err < sizeof(uint32_t) || no_err == -1 ){
		perror("recv message length");
		exit(-1);		
	}
	int dim_buf = ntohl(dim_network);
	if( dim_buf <= 0){
		perror("recv message length not acceptable");
		exit(-1);
	}
	return dim_buf;
}

