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
#include "util.cpp"
#include "crypto.cpp"

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

    cout << "Please, insert your username:" << endl;
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

    while(!rett){
        cout << "Username not valid" << endl;
        cout << "Please, insert a valid username:" << endl;
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
    }

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

    //*************************************************************************************************************
    //              FASE DI AUTENTICAZIONE
    //*************************************************************************************************************

    cout << "Start the AUTHENTICATION PHASE..." << endl << endl;

    //mando lo username
    send_obj(sd, (unsigned char*)username, constants::DIM_USERNAME);

    //ricevo <Ns | certs>
    int size_msg = receive_len(sd);
    unsigned char msg[size_msg];

    receive_obj(sd, msg, size_msg);
    cout << "Received nonce and certificate from server" << endl;

    //array che ospiteranno il nonce e il certificato
    unsigned char nonce_s[constants::NONCE_SIZE];
    int dimOpBuffer = size_msg - constants::NONCE_SIZE;
    unsigned char *serialized_cert;
    X509*cert_s;
	serialized_cert = (unsigned char*) malloc((dimOpBuffer));
	if(!serialized_cert){
		perror("malloc");
		exit(-1);
	}
	
    extract_data_from_array(nonce_s, msg, 0, constants::NONCE_SIZE);
    if(nonce_s == NULL){
		perror("Error during the extraction of the nonce of the server\n");
		exit(-1);
	}
    // serialized_cert conterrà il certificato del server serializzato
    extract_data_from_array(serialized_cert, msg, constants::NONCE_SIZE, size_msg);	
	if(serialized_cert == NULL){
		perror("Error during the extraction of the certificate of the server\n");
		exit(-1);
	}

    cout << "nonce e certificato estratti" << endl;

    unsigned char *pointer;
    pointer = serialized_cert;
	cert_s = d2i_X509(NULL, (const unsigned char**)&charPointer, dimOpBuffer);

    //ora che ho il certificato la serializzazione è inutile
	free(serialized_cert);
    cout << "deserilizzazione fatta" << endl;
    
    // verifica del certificato
    //carico il certificato della CA
    FILE* ca_cert_file = fopen("../data/clients/FoundationsOfCybersecurity_cert.pem", "r");
    if(!ca_cert_file){ 
        cerr << "Error: cannot open file"; 
        exit(1); 
    }
    X509 * ca_cert= PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);

    //carico la certificate revocation list
    FILE* ca_crl_file = fopen("../data/clients/FoundationsOfCybersecurity_crl.pem", "r");
    if(!ca_crl_file){ 
        cerr << "Error: cannot open file"; 
        exit(1); 
    }
    X509_CRL * ca_crl= PEM_read_X509_CRL(ca_crl_file, NULL, NULL, NULL);
    fclose(ca_crl_file);

    cout << "certificati estratti" << endl;
    
    X509_STORE *store_cert= X509_STORE_new(); //alloca uno store vuoto e ritorna
    if(store_cert == NULL){
		perror("Error during the creation of the store\n");
		exit(-1);
	}
    ret= X509_STORE_add_cert(store_cert, ca_cert); //aggiunge un certificato fidato allo store
    if(ret!=1){
        cerr << "Error: cannot add certificate to the store"; 
        exit(1);
    }

    X509_STORE *store_crl= X509_STORE_new();
    ret= X509_STORE_add_crl(store_crl, ca_crl);
    if(ret!=1){
        cerr << "Error: cannot add crl to the store"; 
        exit(1);
    }

    cout << "inizio verifica" << endl;

    rett=verifyCertificate(store_cert, cert_s);
/*
    // contesto per la verifica del certificato
    X509_STORE_CTX *ctx= X509_STORE_CTX_new();
    ret=X509_STORE_CTX_init(ctx, store_cert, cert_s, NULL);
    if(ret!=1){
        cerr << "Error: cannot inizialize the certificate-validation context"; 
        exit(1);
    }

    //varifica certificato
    ret= X509_verify_cert(ctx);
    if(ret<=0){
        cerr << "Error: certificate of server not valid"; 
        exit(1);
    }else{
        cout << "server certificate valid";
    }

    X509_STORE_CTX_free(ctx);

    X509_NAME *server_name = X509_get_subject_name(cert_s);
    X509_NAME *ca_name=X509_get_subject_name(ca_cert);

    EVP_PKEY * pubkey_s= X509_get_pubkey(cert_s);
*/

    if(ret==true)
        cout << "tutto ok" << endl;

    return 0;
}