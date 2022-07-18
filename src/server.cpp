#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "include/constants.h"
#include "crypto.cpp"
//#include "util.cpp"
#include <experimental/filesystem>
#include <filesystem>

using namespace std;
namespace fs = std::experimental::filesystem;

struct user{
    string username;
    //unsigned char* cloudStorage=NULL;
    //string cloudStorage;
    string cloudStorage;

    unsigned int count_client =0;
    unsigned int count_server=0;
};

int main(int argc, char* const argv[]) {
    struct user users[constants::TOT_USERS];
    unsigned int n_users=0;

    int ret, i;
    bool rett;

    int port= constants:: SERVER_PORT;
    unsigned char *msg_to_send;
    int msg_send_len;

    unsigned char *msg_to_receive;
    int msg_receive_len;

    unsigned char *plaintext;
    int pt_len;

    char* charPointer;

    //uso il meccanismo dell'IO multiplexing per gestire richieste provenienti dai client
    fd_set master; //set di descrittori da monitorare
	fd_set reads_fds; //set di descrittori pronti
	int fdmax; //numero massimo di descrittori

    // chiedo la password
    char password[constants::DIM_PASSWORD];
    cout << "Please, insert your password:" << endl;
    memset(password, 0, constants::DIM_PASSWORD);
    if(!fgets(password, constants::DIM_PASSWORD, stdin)){
        perror("Error during the reading from stdin\n");
        exit(-1);
    }
    charPointer = strchr(password, '\n');
    if(charPointer)
        *charPointer = '\0';

    //estraggo chiave privata
    EVP_PKEY * prvKey_s=readPrivateKey("server", password, "server");


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

                    string path=(string)constants::DIR_SERVER + (string)username;
                    
                    const auto processWorkingDir = fs::current_path();
                    const auto existingDir = processWorkingDir / path;

                    if(fs::is_directory(path))
                        cout << "The user \"" << username << "\" is a registered user" << endl;
                    else{
                        cout << "The user \"" << username << "\" is a not registered user" << endl << endl;
                        close(new_fd);
                        continue;
                    }

                    users[n_users].username = username;                    
                    users[n_users].cloudStorage= path;
                    n_users++;


                    //genero N_s
                    unsigned char nonce_s[constants::NONCE_SIZE];
                    generateNonce(nonce_s);

                    //carico il certificato del server
                    X509* cert_server;
                    loadCertificate(cert_server, "server");
                    //buffer che conterrà la serializzazione del certificato
                    unsigned char* cert_buf = NULL;
                    //serializzazione certificato
                    unsigned int cert_size = i2d_X509(cert_server, &cert_buf);

                    if(cert_size < 0) {
                        perror("certificate size error");
                        exit(-1);
                    }

                    sumControl(constants::NONCE_SIZE, cert_size);

                    // mando la dimensione del messaggio <Ns | certs>
                    size_t msg_len= constants::NONCE_SIZE + cert_size;
                    send_int(new_fd, msg_len);

                    // mando il vero messaggio
                    unsigned char msg[msg_len];
                    memset(msg, 0, msg_len);
                    concat2Elements(msg, nonce_s, cert_buf, constants::NONCE_SIZE, cert_size);
                    send_obj(new_fd, msg, msg_len);

                    cout << "Certificate and nonce send to the client" << endl;

                    OPENSSL_free(cert_buf);
	                X509_free(cert_server);

                    //aspetto di ricevere la lunghezza del prossimo messaggio
                    msg_receive_len=receive_len(new_fd);

                    //aspetto di ricevere la lunghezza della firma
                    int signature_len=receive_len(new_fd);

                    //aspetto l'intero messaggio
                    msg_to_receive=(unsigned char*)malloc(msg_receive_len);
                    if(!msg_to_receive){
                        perror("Error during malloc()");
                        exit(-1);
                    }
                    receive_obj(new_fd, msg_to_receive, msg_receive_len);

                    //decifro il messaggio
                    plaintext=from_DigEnv_to_PlainText(msg_to_receive, msg_receive_len, &pt_len, prvKey_s);

                    //estraggo le singole parti dal plaintext <Nc | Yc | sign>
                    unsigned char nonce_c[constants::NONCE_SIZE];
                    extract_data_from_array(nonce_c, plaintext, 0, constants::NONCE_SIZE);
                    if(nonce_c == NULL){
                        perror("Error during the extraction of the client nonce\n");
                        exit(-1);
                    }

                    subControl(msg_receive_len, constants::NONCE_SIZE);
                    subControl(msg_receive_len-constants::NONCE_SIZE, signature_len);
                    int DH_c_len=msg_receive_len-constants::NONCE_SIZE-signature_len;
                    unsigned char serialized_DH_c[DH_c_len];
                    extract_data_from_array(serialized_DH_c, plaintext, constants::NONCE_SIZE, DH_c_len);
                    if(serialized_DH_c == NULL){
                        perror("Error during the extraction of the client DH key\n");
                        exit(-1);
                    }

                    EVP_PKEY *DH_c=deserializePublicKey(serialized_DH_c,  DH_c_len);

                    unsigned char signature[signature_len];
                    extract_data_from_array(signature, plaintext, msg_receive_len-signature_len, msg_receive_len);
                    if(signature == NULL){
                        perror("Error during the extraction of the signature\n");
                        exit(-1);
                    }

                    //carico chiave pubblica del client
                    EVP_PKEY *pubKey_c=getUserPbkey(username);

                    //costruisco messaggio su cui controllare la firma
                    unsigned char *buffer=(unsigned char*)malloc(constants::NONCE_SIZE+constants::NONCE_SIZE+DH_c_len);
                    if(buffer == NULL){
                        perror("Error during malloc()\n");
                        exit(-1);
                    }

                    memcpy(buffer, nonce_c, constants::NONCE_SIZE);
                    concatElements(buffer, nonce_s, constants::NONCE_SIZE, constants::NONCE_SIZE);
                    concatElements(buffer, serialized_DH_c, constants::NONCE_SIZE + constants::NONCE_SIZE, DH_c_len);

                    //verifico firma
                    rett=verifySignature(signature, buffer, signature_len, constants::NONCE_SIZE+constants::NONCE_SIZE+DH_c_len, pubKey_c);
                    if(!rett)
                    {
                        perror("Error during signature verification\n");
                        close(new_fd);
                    }

                    cout << "authenticated client" << endl;
                }
            }
        }
    }

    return 0;
}