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
//#include "util.cpp"
#include "crypto.cpp"

using namespace std;

int main(int argc, char* const argv[]) {
    int ret;
    bool rett;
    int port;
    unsigned char *plaintext;
    unsigned char *chiphertext;
    char * charPointer;
    unsigned char *msg_to_send;
    unsigned char *msg_to_receive;
    int msg_send_len;
    int msg_receive_len;

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

    char username[constants::DIM_USERNAME];

    cout << "Please, insert your username:" << endl;
    memset(username, 0, constants::DIM_USERNAME);
    if(!fgets(username, constants::DIM_USERNAME, stdin)){
        perror("Error during the reading from stdin\n");
        exit(-1);
    }
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
        charPointer = strchr(username, '\n');
        if(charPointer)
            *charPointer = '\0';

        //controllo che lo username non contenga caratteri speciali
        rett = control_white_list(username);
    }

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
    EVP_PKEY * prvKey_c=readPrivateKey(username, password, "client");

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
    msg_to_receive=(unsigned char*)malloc(size_msg);
    if(!msg_to_receive){
		perror("malloc");
		exit(-1);
	}
    //unsigned char msg[size_msg];

    receive_obj(sd, msg_to_receive, size_msg);
    cout << "Received nonce and certificate from server" << endl;

    //array che ospiteranno il nonce e il certificato
    unsigned char nonce_s[constants::NONCE_SIZE];
    int dim_cert_msg = size_msg - constants::NONCE_SIZE;
    unsigned char *serialized_cert;
    X509*cert_s;
	serialized_cert = (unsigned char*) malloc((dim_cert_msg));
	if(!serialized_cert){
		perror("malloc");
		exit(-1);
	}
	
    extract_data_from_array(nonce_s, msg_to_receive, 0, constants::NONCE_SIZE);
    if(nonce_s == NULL){
		perror("Error during the extraction of the nonce of the server\n");
		exit(-1);
	}
    // serialized_cert conterrà il certificato del server serializzato
    extract_data_from_array(serialized_cert, msg_to_receive, constants::NONCE_SIZE, size_msg);	
	if(serialized_cert == NULL){
		perror("Error during the extraction of the certificate of the server\n");
		exit(-1);
	}

    unsigned char *pointer;
    pointer = serialized_cert;
	cert_s = d2i_X509(NULL, (const unsigned char**)&pointer, dim_cert_msg);
    if(!cert_s)
    {
        perror("Error during the deserialization of the server certificate \n");
		exit(-1);
    }

    //ora che ho il certificato la serializzazione è inutile
	free(serialized_cert);

    rett=verifyCertificate(cert_s);
    if(!rett)
    {
        perror("server certificate not valid \n");
		exit(-1);
    }

    //estraggo la chiave pibblica dal certificato del server
    EVP_PKEY* pubKey_s;
    getPublicKeyFromCertificate(cert_s, pubKey_s);

    //genero chiave privata di DH
    EVP_PKEY *DH_prvKey_c=generateDHParams();
    unsigned char* serialized_DH_prvKey_c;

    //rendo la chiave serializzzata per poterla trasmettere
    int len_serialized_prvKey_c=0;
    serialized_DH_prvKey_c=serializePublicKey(DH_prvKey_c, &len_serialized_prvKey_c);
    if(serialized_DH_prvKey_c == NULL){
		perror("Error during serialization of the DH public key\n");
		exit(-1);
	}

    //genero nonce del clint
    unsigned char nonce_c[constants::NONCE_SIZE];
    generateNonce(nonce_c);

    sumControl(constants::NONCE_SIZE, constants::NONCE_SIZE);
	sumControl(constants::NONCE_SIZE + constants::NONCE_SIZE, len_serialized_prvKey_c);
    int pt_len = constants::NONCE_SIZE + constants::NONCE_SIZE + len_serialized_prvKey_c;

    //alloco spazio per il plaintext
    plaintext=(unsigned char*)malloc(pt_len);
    if(!plaintext){
		perror("Error during malloc()");
		exit(-1);
	}

    //creo playntext <Nc | Ns | Yc>
    memcpy(plaintext, nonce_c, constants::NONCE_SIZE);
	concatElements(plaintext, nonce_s, constants::NONCE_SIZE, constants::NONCE_SIZE);
	concatElements(plaintext, serialized_DH_prvKey_c, constants::NONCE_SIZE + constants::NONCE_SIZE, len_serialized_prvKey_c);

    //calcolo firma sul plaintext
    unsigned char *signature=(unsigned char*)malloc(EVP_PKEY_size(prvKey_c));
    if(signature == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
    int signature_len; //conterrà la lunghezza effettiva della firma
    signatureFunction(plaintext, pt_len, signature, &signature_len, prvKey_c);

    sumControl(constants::NONCE_SIZE, len_serialized_prvKey_c);
    sumControl(constants::NONCE_SIZE + len_serialized_prvKey_c, signature_len);

    free(plaintext);
    pt_len=constants::NONCE_SIZE + len_serialized_prvKey_c + signature_len;
    plaintext=(unsigned char*) malloc(pt_len);
    if(!plaintext){
		perror("Error during malloc()");
		exit(-1);
	}

    //creo playntext <Nc | Yc | sign>
    memcpy(plaintext, nonce_c, constants::NONCE_SIZE);
    concatElements(plaintext, serialized_DH_prvKey_c, constants::NONCE_SIZE, len_serialized_prvKey_c);
    concatElements(plaintext, signature, constants::NONCE_SIZE + len_serialized_prvKey_c, signature_len);

    msg_to_send=from_pt_to_DigEnv(plaintext, pt_len, pubKey_s, &msg_send_len);

    //invio lunghezza messaggio
    send_int(sd, msg_send_len);

    //invio lunghezza firma
    send_int(sd, signature_len);

    //invio messaggio
    send_obj(sd, msg_to_send, msg_send_len);
    
    return 0;
}