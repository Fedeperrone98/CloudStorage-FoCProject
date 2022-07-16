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
#include "include/constants.h"
#include "crypto.cpp"
#include "util.cpp"
#include <experimental/filesystem>
#include <filesystem>

using namespace std;
namespace fs = std::experimental::filesystem;

struct user{
    string username;
    string cloudStorage;

    unsigned int count_client =0;
    unsigned int count_server=0;
};

int main(int argc, char* const argv[]) {
    struct user* users[constants::TOT_USERS];
    unsigned int n_users=0;

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

    cout << "Server is listening..." << endl;

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
                    
                    //*************************************************************************************************************
                    //              FASE DI AUTENTICAZIONE
                    //*************************************************************************************************************
                    cout << "Received a connection request" << endl;
                    cout << "Start the AUTHENTICATION PHASE..." << endl << endl;

                    char username[constants::DIM_USERNAME];
                    receive_obj(new_fd, (unsigned char*)username, constants::DIM_USERNAME);

                    cout << "Connection with client: \"" << username << "\"" << endl;

                    const string path= "."+(string)constants::DIR_SERVER + (string)username;
                    
                    const auto processWorkingDir = fs::current_path();
                    const auto existingDir = processWorkingDir / path;

                    if(fs::is_directory(path))
                        cout << "The user \"" << username << "\" is a registered user" << endl;
                    else{
                        cout << "The user \"" << username << "\" is a not registered user" << endl;
                        close(new_fd);
                    }

                    users[n_users]->username = username;
                    users[n_users]->cloudStorage = path;
                    n_users++;

                    //genero N_s
                    unsigned char nonce_s[constants::NONCE_SIZE];
                    generateNonce(nonce_s);

                    //carico il certificato del server
                    X509* cert_server;
                    loadCertificate(cert_server, "server");
                    //buffer che conterrà la serializzazione del certificato
                    unsigned char* cert_buf = NULL;
                    unsigned int size_cert = serializeCertificate(cert_server, cert_buf);

                    sumControl(constants::NONCE_SIZE, size_cert);

                    size_t msg_len= constants::NONCE_SIZE + size_cert;
                    send_int(new_fd, msg_len);

                    unsigned char msg[msg_len];
                    memset(msg, 0, msg_len);
                    concat2Elements(msg, nonce_s, cert_buf, constants::NONCE_SIZE, size_cert);
                    send_obj(new_fd, msg, msg_len);

                    cout << "Certificate and nonce send to the client" << endl;

                    OPENSSL_free(cert_buf);
	                X509_free(cert_server);

                }
            }
        }
    }

    return 0;
}