#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "include/client.h"
#include "include/constants.h"
#include "util.cpp"

using namespace std;

int main(int argc, char* const argv[]) {
    int ret;

    int port;

    //controllo gli argomenti passati al client
    if(argc<=1 || argc >2){
        cout << "Error: insert the client port number\n";
        scanf("%d", &port);
    }else{ 
        port= atoi(argv[1]); //converto il numero di porta in intero 
    }
    
    while( port<1024 || port>65536){
            cout << "Error: insert a valid port number\n";
            scanf("%d", &port);;
    }

    bool rett;
    char username[constants::DIM_USERNAME];

    do{
        cout << "Insert your username:" << endl;
        memset(username, 0, constants::DIM_USERNAME);
        if(!fgets(username, constants::DIM_USERNAME, stdin)){
            perror("Error during the reading from stdin\n");
            exit(-1);
        }
        char * charPointer;
        charPointer = strchr(username, '\n');
        if(charPointer)
            *charPointer = '\0';

        //controllo che lo username non contenga caratteri speciali
        rett = control_white_list(username);
    }while(!rett);

    int sd; //descrittore del socket
    sd= socket(AF_INET,SOCK_STREAM, 0);

    struct sockaddr_in server_addr; //indirizzo del server
    memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port= htons(constants::SERVER_PORT); //numero di porta
	inet_pton(AF_INET, constants::LOCAL_HOST, &server_addr.sin_addr); //indirizzo ip del server

    //invio la richiesta di connessione al server
	ret= connect(sd, (struct sockaddr*)&server_addr, sizeof(server_addr));
	if(ret<0){
		perror("connect");
		exit(-1);	
	}

    cout << "Connection established" << endl;

    send_obj(sd, (unsigned char*)username, constants::DIM_USERNAME);

    return 0;
}