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
#include <experimental/filesystem>
#include <filesystem>

using namespace std;
namespace fs = std::experimental::filesystem;

int main(int argc, char* const argv[]) {
    unsigned int n_users=0;

    int ret, i;
    bool rett;

    int port= constants:: SERVER_PORT;
    unsigned char *msg_to_send;
    int msg_send_len;

    unsigned char *msg_to_receive= NULL;
    int msg_receive_len;

    unsigned char *plaintext=NULL;
    int pt_len;

    char* charPointer;

    //uso il meccanismo dell'IO multiplexing per gestire richieste provenienti dai client
    fd_set master; //set di descrittori da monitorare
	fd_set reads_fds; //set di descrittori pronti
	int fdmax; //numero massimo di descrittori

    // chiedo la password
    char password[constants::DIM_PASSWORD];
    cout << endl <<"Please, insert your password:" << endl;
    memset(password, 0, constants::DIM_PASSWORD);
    if(!fgets(password, constants::DIM_PASSWORD, stdin)){
        perror("Error during the reading from stdin\n");
        exit(-1);
    }
    cout << endl;
    charPointer = strchr(password, '\n');
    if(charPointer)
        *charPointer = '\0';

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

    cout << "Server is listening..." << endl << endl;

    //aggiungo il socket di ascolto al set di descrittori 
    FD_SET(listener, &master);

    //tengo traccia del maggiore
	fdmax=listener;

    //variabile per controllare l'esistenza della cartella degli utenti
    const auto processWorkingDir = fs::current_path();

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
                    cout << "Received a connection request" << endl << endl;
                    cout << "Start the AUTHENTICATION PHASE..." << endl << endl;

                    //estraggo chiave privata
                    EVP_PKEY * prvKey_s=readPrivateKey("server", password, "server");

                    //**************** ricezione primo messaggio *****************

                    char username[constants::DIM_USERNAME];
                    receive_obj(new_fd, (unsigned char*)username, constants::DIM_USERNAME);

                    cout << "Connection with client: \"" << username << "\"" << endl;

                    string path=(string)constants::DIR_SERVER + (string)username;
                    
                    const auto existingDir = processWorkingDir / path;

                    if(fs::is_directory(path))
                        cout << "The user \"" << username << "\" is a registered user" << endl;
                    else{
                        cout << "The user \"" << username << "\" is a not registered user" << endl << endl;
                        close(new_fd);
                        continue;
                    }

                    //**************** invio secondo messaggio *****************

                    //genero N_s
                    unsigned char nonce_s[constants::NONCE_SIZE];
                    generateNonce(nonce_s);                    

                    sumControl(constants::NONCE_SIZE, cert_size);

                    // mando la dimensione del messaggio <Ns | certs>
                    size_t msg_len= constants::NONCE_SIZE + cert_size;
                    send_int(new_fd, msg_len);

                    // mando il vero messaggio
                    unsigned char msg[msg_len];
                    memset(msg, 0, msg_len);
                    concat2Elements(msg, nonce_s, cert_buf, constants::NONCE_SIZE, cert_size);
                    send_obj(new_fd, msg, msg_len);

                    cout << "Sended Certificate and nonce to the client" << endl;

	                X509_free(cert_server);

                    //**************** ricezione terzo messaggio *****************

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
                    
                    cout << "Received message: <EncKey | IV | Nc | Yc | sign>" << endl;

                    plaintext=from_DigEnv_to_PlainText(msg_to_receive, msg_receive_len, &pt_len, prvKey_s);

                    //estraggo le singole parti dal plaintext <Nc | Yc | sign>
                    unsigned char nonce_c[constants::NONCE_SIZE];
                    extract_data_from_array(nonce_c, plaintext, 0, constants::NONCE_SIZE);
                    if(nonce_c == NULL){
                        perror("Error during the extraction of the client nonce\n");
                        exit(-1);
                    }

                    subControl(pt_len, constants::NONCE_SIZE);
                    subControl(pt_len-constants::NONCE_SIZE, signature_len);
                    int DH_c_len=pt_len-constants::NONCE_SIZE-signature_len;
                    unsigned char *serialized_DH_c=(unsigned char*)malloc(DH_c_len);
                    if(!serialized_DH_c){
                        perror("Error during malloc()");
                        exit(-1);
                    }
                    extract_data_from_array(serialized_DH_c, plaintext, constants::NONCE_SIZE, pt_len-signature_len);
                    if(serialized_DH_c == NULL){
                        perror("Error during the extraction of the client DH key\n");
                        exit(-1);
                    }

                    EVP_PKEY *DH_c=deserializePublicKey(serialized_DH_c,  DH_c_len);

                    unsigned char *signature=(unsigned char*)malloc(signature_len);
                    if(signature == NULL){
                        perror("Error during malloc()");
                        exit(-1);
                    }
                    extract_data_from_array(signature, plaintext, pt_len-signature_len, pt_len);
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
                        continue;
                    }

                    cout << "Authenticated client" << endl;

                    free(buffer);
                    free(msg_to_receive);
                    free(serialized_DH_c);
                    free(signature);
                    free(plaintext);

                    // ********************* invio quarto messaggio ************

                    //genero chiave privata di DH
                    EVP_PKEY *DH_prvKey_s=generateDHParams();
                    unsigned char* serialized_DH_prvKey_s;

                    //rendo la chiave serializzata per poterla trasmettere
                    int len_serialized_prvKey_s=0;
                    serialized_DH_prvKey_s=serializePublicKey(DH_prvKey_s, &len_serialized_prvKey_s);
                    if(serialized_DH_prvKey_s == NULL){
                        perror("Error during serialization of the DH public key\n");
                        exit(-1);
                    }

                    //creo plaintext <Nc | Ns | Yc>
                    sumControl(constants::NONCE_SIZE, constants::NONCE_SIZE);
                    sumControl(constants::NONCE_SIZE + constants::NONCE_SIZE, len_serialized_prvKey_s);
                    int pt_len = constants::NONCE_SIZE + constants::NONCE_SIZE + len_serialized_prvKey_s;
                    
                    plaintext=(unsigned char*)malloc(pt_len);
                    if(!plaintext){
                        perror("Error during malloc()");
                        exit(-1);
                    }
                    
                    memcpy(plaintext, nonce_c, constants::NONCE_SIZE);
                    concatElements(plaintext, nonce_s, constants::NONCE_SIZE, constants::NONCE_SIZE);
                    concatElements(plaintext, serialized_DH_prvKey_s, constants::NONCE_SIZE + constants::NONCE_SIZE, len_serialized_prvKey_s);

                    
                    //calcolo firma sul plaintext
                    signature=(unsigned char*)malloc(EVP_PKEY_size(prvKey_s));
                    if(signature == NULL){
                        perror("Error during malloc()");
                        exit(-1);
                    }
                    //signature_len conterrà la lunghezza effettiva della firma
                    signatureFunction(plaintext, pt_len, signature, &signature_len, prvKey_s);

                    sumControl(len_serialized_prvKey_s, signature_len);

                    free(plaintext);
                    pt_len= len_serialized_prvKey_s + signature_len;
                    plaintext=(unsigned char*) malloc(pt_len);
                    if(!plaintext){
                        perror("Error during malloc()");
                        exit(-1);
                    }
                    
                    //creo playntext <Ys | sign>
                    memcpy(plaintext, serialized_DH_prvKey_s, len_serialized_prvKey_s);
                    concatElements(plaintext, signature, len_serialized_prvKey_s, signature_len);

                    msg_to_send=from_pt_to_DigEnv(plaintext, pt_len, pubKey_c, &msg_send_len);
                    
                    //invio lunghezza messaggio
                    send_int(new_fd, msg_send_len);

                    //invio lunghezza firma
                    send_int(new_fd, signature_len);

                    //invio messaggio
                    send_obj(new_fd, msg_to_send, msg_send_len);

                    cout << "Send message: <EncKey | IV | Ys | sign>" << endl;

                    //********* termine invio messaggi per autenticazione ************

                    // derivo chiave di sessione
                    unsigned char* session_key=symmetricKeyDerivation_for_aes_128_gcm(DH_prvKey_s, DH_c);
                    if(session_key==NULL){
                        perror("Error during session key generation\n");
                        exit(-1);
                    }

                    cout << "Session key generation: success" << endl;

                    EVP_PKEY_free(DH_c);
                    EVP_PKEY_free(DH_prvKey_s);
                    EVP_PKEY_free(prvKey_s);
                    EVP_PKEY_free(pubKey_c);

                    free(msg_to_send);
                    free(signature);
                    free(serialized_DH_prvKey_s);

                    cout << endl << "Finish AUTHENTCATION PHASE" << endl << endl;

                    cout << "Start SESSION..." << endl << endl;

                    int count_s=0;
                    int count_c=0;

                    char filename[constants::DIM_FILENAME];
                    long long int dim_file;
                    unsigned char * dim_file_str;

                    while(1){
                        //ricevo la dimensione del messaggio di sessione
                        msg_receive_len = receive_len(new_fd);

                        msg_to_receive= (unsigned char*)malloc(msg_receive_len);
                        if(!msg_to_receive){
                            perror("Error during malloc()");
                            exit(-1);
                        }
                        //ricevo il messaggio di sessione
                        receive_obj(new_fd, msg_to_receive, msg_receive_len);

                        //decifro il messaggio ricevuto
                        plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_c);

                        //estraggo il type
                        unsigned char * type;
                        type= (unsigned char *)malloc(constants::TYPE_CODE_SIZE);                        
                        if(!type){
                            perror("Error during malloc()");
                            exit(-1);
                        }

                        extract_data_from_array(type, plaintext, 0, constants::TYPE_CODE_SIZE);
                        string command=(char*)type;
                        
                        if(command==constants::Upload_request){

                            //******************************************************************************
                            //          UPLOAD
                            //******************************************************************************
                            cout << endl << "Upload request..." << endl;

                            // messaggio di richiesta: <IV | AAD | tag | upload_request | filename | size>

                            //estraggo il filename  
                            extract_data_from_array((unsigned char*)filename, plaintext, constants::TYPE_CODE_SIZE, constants::DIM_FILENAME);
                            
                            //estraggo il size
                            subControl(pt_len,constants::TYPE_CODE_SIZE );
                            subControl(pt_len - constants::TYPE_CODE_SIZE, constants::DIM_FILENAME);
                            int size_dim = pt_len - constants::TYPE_CODE_SIZE - constants::DIM_FILENAME;
                            dim_file_str=(unsigned char *)malloc(size_dim);
                            if(!dim_file_str){
                                perror("malloc(): ");
                                exit(-1);
                            }
                            extract_data_from_array(dim_file_str, plaintext, constants::TYPE_CODE_SIZE+constants::DIM_FILENAME, pt_len);

                            dim_file = strtoll((const char*)dim_file_str, NULL, 10);
                            
                            //creo nuovo file
                            string new_file_name=(string)filename;
                            string path=(string)constants::DIR_SERVER+username+"/"+new_file_name;

                            rett = control_white_list(filename);

                            if(rett==false){
                                send_nack(new_fd, session_key, &count_s);
                                cout << "Upload request: unsuccess" << endl << endl;
                                free(plaintext);
                                free(msg_to_receive);
                                free(type);
                                continue;
                            }
                            
                            if(!access(path.c_str(), 0)){
                                //se il file esiste già devo eliminarlo 
                                remove(path.c_str());                                
                            }
                            //invio ack
                            send_ack(new_fd, session_key, &count_s);

                            FILE* clear_file = fopen(path.c_str(), "a");
                            if(!clear_file) { 
                                perror("Error: cannot open file");
                                exit(1); 
                            }
                            
                            //ciclo per ricevere tanti messaggi in base alla dimensione del file
                            long long int dim_write=0;
                            while(dim_file - dim_write > constants::MAX_READ)
                            {
                                //aspetto di ricevere la dimensione del prossimo messaggio
                                msg_receive_len = receive_len(new_fd);
                                free(msg_to_receive);
                                msg_to_receive= (unsigned char*)malloc(msg_receive_len);
                                if(!msg_to_receive){
                                    perror("Error during malloc()");
                                    exit(-1);
                                }

                                //ricevo il messaggio di sessione
                                receive_obj(new_fd, msg_to_receive, msg_receive_len);
                                cout << "Received message <IV | AAD | tag | file content>" << endl;

                                //decifro il messaggio ricevuto
                                free(plaintext);
                                plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_c);
                                sumControl(dim_write, pt_len);
                                dim_write+=pt_len;

                                ret = fwrite(plaintext, 1, pt_len, clear_file);
                                if(ret < pt_len) { 
                                    perror("Error while writing the file"); 
                                    exit(1); 
                                }
                            }

                            //leggo l'ultimo pezzo

                            //aspetto di ricevere la dimensione del prossimo messaggio
                            msg_receive_len = receive_len(new_fd);
                            free(msg_to_receive);
                            msg_to_receive= (unsigned char*)malloc(msg_receive_len);
                            if(!msg_to_receive){
                                perror("Error during malloc()");
                                exit(-1);
                            }
                            receive_obj(new_fd, msg_to_receive, msg_receive_len);
                            cout << "Received message <IV | AAD | tag | file content>" << endl;

                            //decifro il messaggio ricevuto
                            free(plaintext);
                            plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_c);
                            
                            ret = fwrite(plaintext, 1, dim_file-dim_write, clear_file);
                            
                            if(ret < dim_file-dim_write) { 
                                perror("Error while writing the file"); 
                                exit(1); 
                            }

                            cout << "Upload: success" << endl << endl;

                            fclose(clear_file);
                            free(plaintext);
                            free(type);
                            free(msg_to_receive);

                        }else if(command==constants::Download_request){

                            //******************************************************************************
                            //          DOWNLOAD
                            //******************************************************************************
                            cout << endl << "Download request..." << endl;

                            // messaggio di richiesta: <IV | AAD | tag | download_request | filename >

                            //estraggo il filename  
                            extract_data_from_array((unsigned char*)filename, plaintext, constants::TYPE_CODE_SIZE, constants::DIM_FILENAME);

                            //controllo che il file esista e faccio la canonicalizzazione
                            //creo nuovo file
                            string new_file_name=(string)filename;
                            string path=(string)constants::DIR_SERVER+username+"/"+new_file_name;
                            string canon_file_name = canonicalization(path);
                            rett = control_white_list(filename);

                            if(canon_file_name=="error" || rett==false){
                                send_nack(new_fd, session_key, &count_s);
                                cout << endl;
                                free(plaintext);
                                free(msg_to_receive);
                                free(type);
                                continue;
                            }

                            //apro il file da inviare
                            FILE *clear_file= fopen(canon_file_name.c_str(), "rb");
                            if(!clear_file){
                                perror("Error: cannot open file ");
                                continue;
                            }
                            
                            //leggo la dimensione del file
                            dim_file = fs::file_size(canon_file_name);

                            // messaggio di richiesta: <IV | AAD | tag | upload_request | filename | size>
                            type=(unsigned char*)malloc(constants::TYPE_CODE_SIZE);
                            if(type == NULL){
                                perror("Error during malloc()\n");
                                exit(-1);
                            }
                            memcpy(type, constants::Size, constants::TYPE_CODE_SIZE);

                            sumControl(constants::TYPE_CODE_SIZE , sizeof(to_string(dim_file)));
                            pt_len = constants::TYPE_CODE_SIZE  + sizeof(to_string(dim_file));
                            plaintext = (unsigned char *)malloc(pt_len);
                            if (!plaintext)
                            {
                                perror("Error during malloc()");
                                exit(-1);
                            }
                            memcpy(plaintext, type, constants::TYPE_CODE_SIZE);
                            concatElements(plaintext, (unsigned char*)to_string(dim_file).c_str(), constants::TYPE_CODE_SIZE, sizeof(to_string(dim_file)));

                            msg_to_send= symmetricEncryption(plaintext, pt_len, session_key, &msg_send_len, &count_s);

                            send_int(new_fd, msg_send_len);
                            send_obj(new_fd, msg_to_send, msg_send_len);
                            free(msg_to_send);

                            cout << "Sendend message <IV | AAD | tag | Size_type | size file>" << endl;

                            //leggo il contenuto del file
                            long long int dim_read=0;

                            while(dim_file - dim_read > constants::MAX_READ){

                                free(plaintext);
                                plaintext= (unsigned char*)malloc(constants::MAX_READ);
                                if(!plaintext){
                                    perror("Error during malloc()");
                                    exit(-1);
                                }
                                ret= fread(plaintext, 1, constants::MAX_READ, clear_file);
                                if(ret<constants::MAX_READ){
                                    perror("Error while reading file");
                                    exit(1);
                                }
                                
                                //mando il file un pezzo per volta
                                // messaggio: <IV | AAD | tag | file_content>

                                msg_to_send= symmetricEncryption(plaintext, constants::MAX_READ, session_key, &msg_send_len, &count_s);

                                send_int(new_fd, msg_send_len);
                                send_obj(new_fd, msg_to_send, msg_send_len);

                                cout << "Sendend message <IV | AAD | tag | file content>" << endl;

                                free(msg_to_send);

                                sumControl(dim_read, constants::MAX_READ);
                                dim_read+=constants::MAX_READ;

                            }

                            free(plaintext);
                            plaintext= (unsigned char*)malloc(dim_file - dim_read);
                            if(!plaintext){
                                perror("Error during malloc()");
                                exit(-1);
                            }
                            ret= fread(plaintext, 1, dim_file-dim_read, clear_file);
                            if(ret<dim_file-dim_read){
                                perror("Error while reading file");
                                exit(1);
                            }

                            // messaggio: <IV | AAD | tag | file_content>

                            msg_to_send= symmetricEncryption(plaintext, dim_file-dim_read, session_key, &msg_send_len, &count_s);

                            send_int(new_fd, msg_send_len);
                            send_obj(new_fd, msg_to_send, msg_send_len);
                            free(msg_to_send);

                            cout << "Sendend message <IV | AAD | tag | file content>" << endl;
                            cout << "Download request: success" << endl << endl;

                            fclose(clear_file);
                            free(plaintext);
                            free(msg_to_receive);

                        }else if(command==constants::Delete_request){

                            //******************************************************************************
                            //          DELETE
                            //******************************************************************************
                            cout << endl << "Delete request..." << endl;

                            //estraggo il filename  
                            extract_data_from_array((unsigned char*)filename, plaintext, constants::TYPE_CODE_SIZE, constants::DIM_FILENAME);

                            //controllo che il file esista e faccio la canonicalizzazione
                            //creo nuovo file
                            string new_file_name=(string)filename;
                            string path=(string)constants::DIR_SERVER+username+"/"+new_file_name;
                            string canon_file_name = canonicalization(path);

                            if(canon_file_name=="error"){
                                send_nack(new_fd, session_key, &count_s);
                                cout << "Delete request: unsuccess" << endl << endl;
                                free(plaintext);
                                free(msg_to_receive);
                                free(type);
                                continue;
                            }

                            pt_len = constants::TYPE_CODE_SIZE;
                            plaintext = (unsigned char *)malloc(pt_len);
                            if (!plaintext)
                            {
                                perror("Error during malloc()");
                                exit(-1);
                            }
                            memcpy(plaintext, constants::Ask_confirmation, constants::TYPE_CODE_SIZE);

                            msg_to_send= symmetricEncryption(plaintext, pt_len, session_key, &msg_send_len, &count_s);

                            send_int(new_fd, msg_send_len);
                            send_obj(new_fd, msg_to_send, msg_send_len);
                            free(msg_to_send);

                            cout << "Sended message: <IV | AAD | tag | Ask_confirmation_type >" << endl;

                            msg_receive_len = receive_len(new_fd);
                            free(msg_to_receive);
                            msg_to_receive= (unsigned char*)malloc(msg_receive_len);
                            if(!msg_to_receive){
                                perror("Error during malloc()");
                                exit(-1);
                            }
                            receive_obj(new_fd, msg_to_receive, msg_receive_len);

                            // decifro il messaggio
                            free(plaintext);
                            plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_c); 

                            if(!strncmp((const char*)plaintext, constants::Not_acknowledgment, sizeof(constants::Not_acknowledgment)))
                            {
                                cout << "Received message <IV | AAD | tag | Not_acknowledgement_type>" << endl;
                                cout << "Delete request: unsuccess" << endl << endl;

                                free(plaintext);
                                free(msg_to_receive);
                                free(type);

                                continue;
                            }else{
                                cout << "Received message <IV | AAD | tag | Acknowledgement_type>" << endl;
                                remove(canon_file_name.c_str());
                                send_ack(new_fd, session_key, &count_s);
                                 cout << "Delete request: success" << endl << endl;

                                free(plaintext);
                                free(msg_to_receive);
                                free(type);
                            }

                        }else if(command==constants::List_request){

                            //******************************************************************************
                            //          LIST
                            //******************************************************************************
                            cout << endl << "List request..." << endl;

                            string path=(string)constants::DIR_SERVER+username;
                            string list="";
                            int count=0;
                            string file_key=username+(string)constants::SUFFIX_PUBKEY;

                            for (const auto & file : fs::directory_iterator(path)){
                                if (fs::path(file).filename().string()==file_key)
                                    continue;

                                if(count==0){
                                    list.append(fs::path(file).filename().string());
                                    count=1;
                                    continue;
                                }
                                    
                                list.append(","+fs::path(file).filename().string());
                            }

                            //cout << "list: " << list << endl;

                            type=(unsigned char*)malloc(constants::TYPE_CODE_SIZE);
                            if(type == NULL){
                                perror("Error during malloc()\n");
                                exit(-1);
                            }
                            memcpy(type, constants::List_file, constants::TYPE_CODE_SIZE);

                            sumControl(constants::TYPE_CODE_SIZE, list.size() );
                            pt_len = constants::TYPE_CODE_SIZE + list.size() ;
                            plaintext = (unsigned char *)malloc(pt_len);
                            if (!plaintext)
                            {
                                perror("Error during malloc()");
                                exit(-1);
                            }
                            memcpy(plaintext, type, constants::TYPE_CODE_SIZE);
                            concatElements(plaintext, (unsigned char*)list.c_str(), constants::TYPE_CODE_SIZE, list.size());
                            
                            msg_to_send= symmetricEncryption(plaintext, pt_len, session_key, &msg_send_len, &count_s);

                            send_int(new_fd, msg_send_len);
                            send_obj(new_fd, msg_to_send, msg_send_len);
                            free(msg_to_send);

                            cout << "Sended message: <IV | AAD | tag | List_file | list >" << endl;



                        }else if(command==constants::Rename_request){

                            //******************************************************************************
                            //          RENAME
                            //******************************************************************************
                            cout << endl << "Rename request..." << endl;

                            char old_filename[constants::DIM_FILENAME];
                            char new_filename[constants::DIM_FILENAME];

                            //estraggo old_filename  
                            extract_data_from_array((unsigned char*)old_filename, plaintext, constants::TYPE_CODE_SIZE, constants::DIM_FILENAME);
                            //estraggo new_filename  
                            extract_data_from_array((unsigned char*)new_filename, plaintext, constants::TYPE_CODE_SIZE+constants::DIM_FILENAME, pt_len);

                            //controllo che il file esista e faccio la canonicalizzazione
                            //creo nuovo file
                            string temp =(string)old_filename;
                            string old_path=(string)constants::DIR_SERVER+username+"/"+ temp;
                            string old_canon_file_name = canonicalization(path);

                            rett = control_white_list(new_filename);

                            if(old_canon_file_name=="error" || rett==false){
                                send_nack(new_fd, session_key, &count_s);
                                cout << "Rename request: unsuccess" << endl << endl;
                                free(plaintext);
                                free(msg_to_receive);
                                free(type);
                                continue;
                            }

                            string new_path=(string)constants::DIR_SERVER+username+"/"+(string)new_filename;

                            ret= rename(old_path.c_str(), new_path.c_str());
                            if(!ret){
                                send_ack(new_fd, session_key, &count_s);
                                cout << "Rename request: success" << endl << endl;
                                free(plaintext);
                                free(msg_to_receive);
                                free(type);

                            }else{
                                send_nack(new_fd, session_key, &count_s);
                                cout << "Rename request: unsuccess" << endl << endl;
                                free(plaintext);
                                free(msg_to_receive);
                                free(type);
                                continue;

                            }                            

                        }else if(command==constants::Logout_request)
                        {
                            //******************************************************************************
                            //          LOGOUT
                            //******************************************************************************
                            
                            cout << endl << "Logout request..." << endl;

                            send_ack(new_fd, session_key, &count_s);

                            cout << "Logout: success" << endl << endl;

                            free(session_key);
                            free(plaintext);
                            free(type);
                            free(msg_to_receive);

                            close(new_fd);
                            break;

                        }else {

                            cout << endl <<"Received invalid request" << endl;

                        }
                    }
                    close(new_fd);
                }
            }
        }
    }

    return 0;
}