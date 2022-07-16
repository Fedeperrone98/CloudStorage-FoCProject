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
#include "include/server.h"
#include "include/constants.h"
#include "util.cpp"
#include <filesystem>

using namespace std;

int main(int argc, char* const argv[]) {
    int ret, i;

    int port= constants:: SERVER_PORT;

    //uso il meccanismo dell'IO multiplexing per gestire richieste provenienti dai client
    fd_set master; //set di descrittori da monitorare
	fd_set reads_fds; //set di descrittori pronti
	int fdmax; //numero massimo di descrittori

    //azzero i set dei descrittori
	FD_ZERO(&master);
	FD_ZERO(&reads_fds);

    struct sockaddr_in server_addr; //indirizzo del server
    struct sockaddr_in client_addr; //indirizzo del client
    socklen_t addr_len;

    //creazione indirizzo del server
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port= htons(port); //numero di porta
	server_addr.sin_addr.s_addr= INADDR_ANY; //metto il server in ascolto su tutte le interfacce

    int listener; //socket di ascolto
    listener= socket(AF_INET, SOCK_STREAM, 0);
    int new_fd; //socket di comunicazione

    //associo l'indirizzo del server al socket di ascolto
    ret= bind(listener, (struct sockaddr*)& server_addr, sizeof(server_addr));
    if(ret<0){
        perror("bind");
        exit(-1);
    }

    ret= listen(listener, constants::MAX_CLIENTS);
    if(ret<0){
        perror("listen");
        exit(-1);
    }

    cout << "Server is listening" << endl;

    //aggiungo il socket di ascolto al set di descrittori 
    FD_SET(listener, &master);

    //tengo traccia del maggiore
	fdmax=listener;

    while(1){
        reads_fds=master;

        //mi blocco (potenzialmente) in attesa dei descrittori pronti
		//attesa senza timeout (passo NULL all'ultimo parametro della select)
		select(fdmax+1, &reads_fds, NULL, NULL, NULL);

        //scorro il set dei descrittori 
		for(i=0; i<=fdmax; i++){ 
            //descrittore pronto (reads_fs contiene l'insieme di descrittori pronti)
            if(FD_ISSET(i, &reads_fds)){
                
                if(i==listener){ //il descrittore pronto è il listener, quindi ho ricevuto una richiesta di connessione da un client

                    addr_len= sizeof(client_addr);
                    
                    //accetto la richiesta di connessione del client
                    new_fd= accept(listener, (struct sockaddr *)& client_addr, &addr_len);
                    
                    //aggiungo il nuovo socket al set
                    FD_SET(new_fd, &master);

                    //aggiorni fdmax
                    if(new_fd> fdmax){
                        fdmax = new_fd;
                    }

                }else{ //il descrittore pronto non è il listener, ma un altro (socket di comunicazione con i client)

                    //fase di autenticazione
                    char username[constants::DIM_USERNAME];
                    receive_obj(new_fd, (unsigned char*)username, constants::DIM_USERNAME);

                    cout << "Connection with client: " << username << endl;

                    string path= (string)constants::DIR_SERVER + (string)username;
                    namespace fs = std::filesystem;

                }
            }
        }
    }

    return 0;
}