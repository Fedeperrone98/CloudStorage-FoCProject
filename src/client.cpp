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

using namespace std;
namespace fs = std::experimental::filesystem;

int main(int argc, char *const argv[])
{
    int ret;
    bool rett;
    int port;
    unsigned char *plaintext;
    unsigned char *chiphertext;
    char *charPointer;
    unsigned char *msg_to_send;
    unsigned char *msg_to_receive;
    int msg_send_len;
    int msg_receive_len;

    // controllo gli argomenti passati al client
    if (argc <= 1 || argc > 2)
    {
        cout << "Error: insert the client port number\n";
        cin >> port;
        while ('\n' != getchar());
    }
    else
    {
        port = atoi(argv[1]); // converto il numero di porta in intero
    }

    while (port < 1024 || port > 65536)
    {
        cout << "Error: insert a valid port number\n";
        cin >> port;
        while ('\n' != getchar());
    }

    char username[constants::DIM_USERNAME];

    cout << endl
         << "Please, insert your username:" << endl;
    memset(username, 0, constants::DIM_USERNAME);
    if (!fgets(username, constants::DIM_USERNAME, stdin))
    {
        perror("Error during the reading from stdin\n");
        exit(-1);
    }
    charPointer = strchr(username, '\n');
    if (charPointer)
        *charPointer = '\0';

    // controllo che lo username non contenga caratteri speciali
    rett = control_white_list(username);

    while (!rett)
    {
        cout << "Username not valid" << endl;
        cout << "Please, insert a valid username:" << endl;
        memset(username, 0, constants::DIM_USERNAME);
        if (!fgets(username, constants::DIM_USERNAME, stdin))
        {
            perror("Error during the reading from stdin\n");
            exit(-1);
        }
        charPointer = strchr(username, '\n');
        if (charPointer)
            *charPointer = '\0';

        // controllo che lo username non contenga caratteri speciali
        rett = control_white_list(username);
    }

    // chiedo la password
    char password[constants::DIM_PASSWORD];
    cout << endl
         << "Please, insert your password:" << endl;
    memset(password, 0, constants::DIM_PASSWORD);
    if (!fgets(password, constants::DIM_PASSWORD, stdin))
    {
        perror("Error during the reading from stdin\n");
        exit(-1);
    }
    charPointer = strchr(password, '\n');
    if (charPointer)
        *charPointer = '\0';

    // estraggo chiave privata
    EVP_PKEY *prvKey_c = readPrivateKey(username, password, "client");

    int sd; // descrittore del socket
    sd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr; // indirizzo del server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(constants::SERVER_PORT);             // numero di porta
    inet_pton(AF_INET, constants::LOCAL_HOST, &server_addr.sin_addr); // indirizzo ip del server

    // invio la richiesta di connessione al server
    ret = connect(sd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0)
    {
        perror("connect");
        exit(-1);
    }

    cout << endl
         << "Connection established" << endl;

    //*************************************************************************************************************
    //              FASE DI AUTENTICAZIONE
    //*************************************************************************************************************

    cout << endl
         << "Start the AUTHENTICATION PHASE..." << endl
         << endl;

    //**************** invio primo messaggio *****************

    // mando lo username
    send_obj(sd, (unsigned char *)username, constants::DIM_USERNAME);
    cout << "Send the username to the server" << endl;

    //**************** ricezione secondo messaggio *****************

    // ricevo <Ns | certs>
    int size_msg = receive_len(sd);
    msg_to_receive = (unsigned char *)malloc(size_msg);
    if (!msg_to_receive)
    {
        perror("malloc");
        exit(-1);
    }

    receive_obj(sd, msg_to_receive, size_msg);
    cout << "Received nonce and certificate from server" << endl;

    // array che ospiteranno il nonce e il certificato
    unsigned char nonce_s[constants::NONCE_SIZE];
    int dim_cert_msg = size_msg - constants::NONCE_SIZE;
    unsigned char *serialized_cert;
    X509 *cert_s;
    serialized_cert = (unsigned char *)malloc((dim_cert_msg));
    if (!serialized_cert)
    {
        perror("malloc");
        exit(-1);
    }

    extract_data_from_array(nonce_s, msg_to_receive, 0, constants::NONCE_SIZE);
    if (nonce_s == NULL)
    {
        perror("Error during the extraction of the nonce of the server\n");
        exit(-1);
    }
    // serialized_cert conterrà il certificato del server serializzato
    extract_data_from_array(serialized_cert, msg_to_receive, constants::NONCE_SIZE, size_msg);
    if (serialized_cert == NULL)
    {
        perror("Error during the extraction of the certificate of the server\n");
        exit(-1);
    }

    unsigned char *pointer;
    pointer = serialized_cert;
    cert_s = d2i_X509(NULL, (const unsigned char **)&pointer, dim_cert_msg);
    if (!cert_s)
    {
        perror("Error during the deserialization of the server certificate \n");
        exit(-1);
    }

    // ora che ho il certificato la serializzazione è inutile
    free(serialized_cert);

    rett = verifyCertificate(cert_s);
    if (!rett)
    {
        perror("server certificate not valid \n");
        exit(-1);
    }
    cout << "received valid cert" << endl;

    //********** invio terzo messaggio **********

    // estraggo la chiave pibblica dal certificato del server
    EVP_PKEY *pubKey_s;
    getPublicKeyFromCertificate(cert_s, pubKey_s);

    // genero chiave privata di DH
    EVP_PKEY *DH_prvKey_c = generateDHParams();
    unsigned char *serialized_DH_prvKey_c;

    // rendo la chiave serializzzata per poterla trasmettere
    int len_serialized_prvKey_c = 0;
    serialized_DH_prvKey_c = serializePublicKey(DH_prvKey_c, &len_serialized_prvKey_c);
    if (serialized_DH_prvKey_c == NULL)
    {
        perror("Error during serialization of the DH public key\n");
        exit(-1);
    }

    // genero nonce del client
    unsigned char nonce_c[constants::NONCE_SIZE];
    generateNonce(nonce_c);

    sumControl(constants::NONCE_SIZE, constants::NONCE_SIZE);
    sumControl(constants::NONCE_SIZE + constants::NONCE_SIZE, len_serialized_prvKey_c);
    int pt_len = constants::NONCE_SIZE + constants::NONCE_SIZE + len_serialized_prvKey_c;

    plaintext = (unsigned char *)malloc(pt_len);
    if (!plaintext)
    {
        perror("Error during malloc()");
        exit(-1);
    }

    // creo plaintext <Nc | Ns | Yc>
    memcpy(plaintext, nonce_c, constants::NONCE_SIZE);
    concatElements(plaintext, nonce_s, constants::NONCE_SIZE, constants::NONCE_SIZE);
    concatElements(plaintext, serialized_DH_prvKey_c, constants::NONCE_SIZE + constants::NONCE_SIZE, len_serialized_prvKey_c);

    // calcolo firma sul plaintext
    unsigned char *signature = (unsigned char *)malloc(EVP_PKEY_size(prvKey_c));
    if (signature == NULL)
    {
        perror("Error during malloc()");
        exit(-1);
    }
    int signature_len; // conterrà la lunghezza effettiva della firma
    signatureFunction(plaintext, pt_len, signature, &signature_len, prvKey_c);

    sumControl(constants::NONCE_SIZE, len_serialized_prvKey_c);
    sumControl(constants::NONCE_SIZE + len_serialized_prvKey_c, signature_len);

    free(plaintext);
    pt_len = constants::NONCE_SIZE + len_serialized_prvKey_c + signature_len;
    plaintext = (unsigned char *)malloc(pt_len);
    if (!plaintext)
    {
        perror("Error during malloc()");
        exit(-1);
    }

    // creo playntext <Nc | Yc | sign>
    memcpy(plaintext, nonce_c, constants::NONCE_SIZE);
    concatElements(plaintext, serialized_DH_prvKey_c, constants::NONCE_SIZE, len_serialized_prvKey_c);
    concatElements(plaintext, signature, constants::NONCE_SIZE + len_serialized_prvKey_c, signature_len);

    msg_to_send = from_pt_to_DigEnv(plaintext, pt_len, pubKey_s, &msg_send_len);

    // invio lunghezza messaggio
    send_int(sd, msg_send_len);

    // invio lunghezza firma
    send_int(sd, signature_len);

    // invio messaggio
    send_obj(sd, msg_to_send, msg_send_len);

    cout << "Sended message: <EncKey | IV | Nc | Yc | sign>" << endl;

    free(msg_to_receive);
    free(msg_to_send);
    free(serialized_DH_prvKey_c);
    free(signature);

    //************** ricezione quarto messaggio *****************

    // aspetto di ricevere la lunghezza del prossimo messaggio
    msg_receive_len = receive_len(sd);

    // aspetto di ricevere la lunghezza della firma
    signature_len = receive_len(sd);

    // aspetto l'intero messaggio
    msg_to_receive = (unsigned char *)malloc(msg_receive_len);
    if (!msg_to_receive)
    {
        perror("Error during malloc()");
        exit(-1);
    }
    receive_obj(sd, msg_to_receive, msg_receive_len);

    cout << "Received message: <EncKey | IV | Ys | sign>" << endl;

    // decifro il messaggio
    plaintext = from_DigEnv_to_PlainText(msg_to_receive, msg_receive_len, &pt_len, prvKey_c);

    // estraggo le singole parti dal plaintext <Ys | sign>
    subControl(pt_len, signature_len);
    int DH_s_len = pt_len - signature_len;
    unsigned char *serialized_DH_s = (unsigned char *)malloc(DH_s_len);
    if (serialized_DH_s == NULL)
    {
        perror("Error during malloc()\n");
        exit(-1);
    }
    extract_data_from_array(serialized_DH_s, plaintext, 0, pt_len - signature_len);
    if (serialized_DH_s == NULL)
    {
        perror("Error during the extraction of the server DH key\n");
        exit(-1);
    }

    EVP_PKEY *DH_s = deserializePublicKey(serialized_DH_s, DH_s_len);

    signature = (unsigned char *)malloc(signature_len);
    if (signature == NULL)
    {
        perror("Error during malloc()\n");
        exit(-1);
    }

    extract_data_from_array(signature, plaintext, pt_len - signature_len, pt_len);
    if (signature == NULL)
    {
        perror("Error during the extraction of the signature\n");
        exit(-1);
    }

    // costruisco messaggio su cui controllare la firma
    unsigned char *buffer = (unsigned char *)malloc(constants::NONCE_SIZE + constants::NONCE_SIZE + DH_s_len);
    if (buffer == NULL)
    {
        perror("Error during malloc()\n");
        exit(-1);
    }

    memcpy(buffer, nonce_c, constants::NONCE_SIZE);
    concatElements(buffer, nonce_s, constants::NONCE_SIZE, constants::NONCE_SIZE);
    concatElements(buffer, serialized_DH_s, constants::NONCE_SIZE + constants::NONCE_SIZE, DH_s_len);

    rett = verifySignature(signature, buffer, signature_len, constants::NONCE_SIZE + constants::NONCE_SIZE + DH_s_len, pubKey_s);
    if (!rett)
    {
        perror("Error during signature verification\n");
        exit(-1);
    }

    cout << "Authenticated server" << endl;

    //********* termine invio messaggi per autenticazione ************

    // derivo chiave di sessione
    unsigned char *session_key = symmetricKeyDerivation_for_aes_128_gcm(DH_prvKey_c, DH_s);
    if (session_key == NULL)
    {
        perror("Error during session key generation\n");
        exit(-1);
    }

    cout << "Session key generation: success" << endl
         << endl;

    EVP_PKEY_free(DH_s);
    EVP_PKEY_free(DH_prvKey_c);
    EVP_PKEY_free(prvKey_c);
    EVP_PKEY_free(pubKey_s);

    free(buffer);
    free(msg_to_receive);
    free(serialized_DH_s);
    free(signature);
    free(plaintext);

    cout << "Finish AUTHENTCATION PHASE" << endl
         << endl;

    cout << "Start SESSION..." << endl
         << endl;

    int count_s = 0;
    int count_c = 0;
    unsigned char *array= NULL;
    char filename[constants::DIM_FILENAME];
    string canon_file_name;
    FILE *clear_file;
    string path;
    long long int dim_file;
    while (1)
    {
        cout << "*********************MENU*****************" << endl;
        cout << "1) Upload" << endl;
        cout << "2) Download" << endl;
        cout << "3) Delete" << endl;
        cout << "4) List" << endl;
        cout << "5) Rename" << endl;
        cout << "6) Logout" << endl;
        cout << "******************************************" << endl;
        cout << "Insert the chosen code operation" << endl;

        int operation;
        cin >> operation;
        while ('\n' != getchar());
        
        free(array);

        switch (operation)
        {
        case 1:
            //******************************************************************************
            //          UPLOAD
            //******************************************************************************
            //chiedo il file da caricare
            cout << endl << "Please, type the file to upload: " << endl;
            memset(filename, 0, constants::DIM_FILENAME);
            if (!fgets(filename, constants::DIM_FILENAME, stdin))
            {
                perror("Error during the reading from stdin\n");
                exit(-1);
            }
            charPointer = strchr(filename, '\n');
            if (charPointer)
                *charPointer = '\0';
            
            // controllo che il filename non contenga caratteri speciali
            rett = control_white_list(filename);
            path = (string)constants::DIR_CLIENTS + (string)username + "/" + filename;
            canon_file_name = canonicalization(path);
            while (!rett || canon_file_name=="error")
            {
                cout << "Filename not valid" << endl;
                cout << "Please, insert a valid filename:" << endl;
                memset(filename, 0, constants::DIM_FILENAME);
                if (!fgets(filename, constants::DIM_FILENAME, stdin))
                {
                    perror("Error during the reading from stdin\n");
                    exit(-1);
                }
                charPointer = strchr(filename, '\n');
                if (charPointer)
                    *charPointer = '\0';

                // controllo che lo username non contenga caratteri speciali
                rett = control_white_list(filename);

                path = (string)constants::DIR_CLIENTS + (string)username + "/" + filename;
                canon_file_name = canonicalization(path);
            }
            
            //apro il file da caricare
            clear_file= fopen(canon_file_name.c_str(), "rb");
            if(!clear_file){
                perror("Error: cannot open file ");
                continue;
            }
            
            //leggo la dimensione del file
            dim_file = fs::file_size(canon_file_name);

            // messaggio di richiesta: <IV | AAD | tag | upload_request | filename | size>
            array=(unsigned char*)malloc(constants::TYPE_CODE_SIZE);
            if(array == NULL){
                perror("Error during malloc()\n");
                exit(-1);
            }
            memcpy(array, constants::Upload_request, constants::TYPE_CODE_SIZE);

            sumControl(constants::TYPE_CODE_SIZE, sizeof(filename) );
            sumControl(constants::TYPE_CODE_SIZE + sizeof(filename), sizeof(to_string(dim_file)));
            pt_len = constants::TYPE_CODE_SIZE + sizeof(filename) + sizeof(to_string(dim_file));
            plaintext = (unsigned char *)malloc(pt_len);
            if (!plaintext)
            {
                perror("Error during malloc()");
                exit(-1);
            }
            memcpy(plaintext, array, constants::TYPE_CODE_SIZE);
            concatElements(plaintext, (unsigned char*)filename, constants::TYPE_CODE_SIZE, sizeof(filename));
            concatElements(plaintext, (unsigned char*)to_string(dim_file).c_str(), constants::TYPE_CODE_SIZE + sizeof(filename), sizeof(to_string(dim_file)));

            msg_to_send= symmetricEncryption(plaintext, pt_len, session_key, &msg_send_len, &count_c);

            send_int(sd, msg_send_len);
            send_obj(sd, msg_to_send, msg_send_len);
            free(msg_to_send);

            cout << "Sended message: <IV | AAD | tag | upload_request | filename | size>" << endl;

            // ricevo l'ack
            msg_receive_len = receive_len(sd);
            msg_to_receive= (unsigned char*)malloc(msg_receive_len);
            if(!msg_to_receive){
                perror("Error during malloc()");
                exit(-1);
            }
            receive_obj(sd, msg_to_receive, msg_receive_len);

            // decifro il messaggio
            free(plaintext);
            plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s);
            
            if(!strncmp((const char*)plaintext, constants::Acknowledgment, sizeof(constants::Acknowledgment)))
            {
                cout << "Received message <IV | AAD | tag | Acknowledgement_type>" << endl;

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

                    msg_to_send= symmetricEncryption(plaintext, constants::MAX_READ, session_key, &msg_send_len, &count_c);

                    send_int(sd, msg_send_len);
                    send_obj(sd, msg_to_send, msg_send_len);

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

                msg_to_send= symmetricEncryption(plaintext, dim_file-dim_read, session_key, &msg_send_len, &count_c);

                send_int(sd, msg_send_len);
                send_obj(sd, msg_to_send, msg_send_len);
                free(msg_to_send);

                cout << "Sendend message <IV | AAD | tag | file content>" << endl;
                cout << "Upload request: success" << endl << endl;

                fclose(clear_file);
                free(plaintext);
                free(msg_to_receive);

            }else{
                cout << "Received message <IV | AAD | tag | Not_Acknowledgement_type>" << endl;
                cout << "Upload request: unsuccess" << endl << endl;

                free(plaintext);
                free(msg_to_receive);

                continue;
            }

            break;
        
        case 2:
            //******************************************************************************
            //          DOWNLOAD
            //******************************************************************************

            //chiedo il file da scaricare
            cout << endl << "Please, type the file to download: " << endl;
            memset(filename, 0, constants::DIM_FILENAME);
            if (!fgets(filename, constants::DIM_FILENAME, stdin))
            {
                perror("Error during the reading from stdin\n");
                exit(-1);
            }
            charPointer = strchr(filename, '\n');
            if (charPointer)
                *charPointer = '\0';
            
            // controllo che il filename non contenga caratteri speciali
            rett = control_white_list(filename);
            while (!rett)
            {
                cout << "Filename not valid" << endl;
                cout << "Please, insert a valid filename:" << endl;
                memset(filename, 0, constants::DIM_FILENAME);
                if (!fgets(filename, constants::DIM_FILENAME, stdin))
                {
                    perror("Error during the reading from stdin\n");
                    exit(-1);
                }
                charPointer = strchr(filename, '\n');
                if (charPointer)
                    *charPointer = '\0';

                // controllo che lo filename non contenga caratteri speciali
                rett = control_white_list(filename);
            }

            // messaggio di richiesta: <IV | AAD | tag | download_request | filename >
            array=(unsigned char*)malloc(constants::TYPE_CODE_SIZE);
            if(array == NULL){
                perror("Error during malloc()\n");
                exit(-1);
            }
            memcpy(array, constants::Download_request, constants::TYPE_CODE_SIZE);

            sumControl(constants::TYPE_CODE_SIZE, sizeof(filename) );
            pt_len = constants::TYPE_CODE_SIZE + sizeof(filename) ;
            plaintext = (unsigned char *)malloc(pt_len);
            if (!plaintext)
            {
                perror("Error during malloc()");
                exit(-1);
            }
            memcpy(plaintext, array, constants::TYPE_CODE_SIZE);
            concatElements(plaintext, (unsigned char*)filename, constants::TYPE_CODE_SIZE, sizeof(filename));

            msg_to_send= symmetricEncryption(plaintext, pt_len, session_key, &msg_send_len, &count_c);

            send_int(sd, msg_send_len);
            send_obj(sd, msg_to_send, msg_send_len);
            free(msg_to_send);

            cout << "Sended message: <IV | AAD | tag | download_request | filename >" << endl;

            msg_receive_len = receive_len(sd);
            msg_to_receive= (unsigned char*)malloc(msg_receive_len);
            if(!msg_to_receive){
                perror("Error during malloc()");
                exit(-1);
            }
            receive_obj(sd, msg_to_receive, msg_receive_len);

            // decifro il messaggio
            free(plaintext);
            plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s);  

            if(!strncmp((const char*)plaintext, constants::Not_acknowledgment, sizeof(constants::Not_acknowledgment)))
            {
                cout << "Received message <IV | AAD | tag | Not_Acknowledgement_type>" << endl;
                cout << "File doesn't exist" << endl;
                cout << "Download request: unsuccess" << endl << endl;

                free(plaintext);
                free(msg_to_receive);

                continue;

            }else{

                cout << "Received message <IV | AAD | tag | Size_type | size file>" << endl;

                //estraggo il size
                subControl(pt_len,constants::TYPE_CODE_SIZE );
                int size_dim = pt_len - constants::TYPE_CODE_SIZE;
                unsigned char * dim_file_str=(unsigned char *)malloc(size_dim);
                if(!dim_file_str){
                    perror("malloc(): ");
                    exit(-1);
                }
                extract_data_from_array(dim_file_str, plaintext, constants::TYPE_CODE_SIZE, pt_len);

                dim_file = strtoll((const char*)dim_file_str, NULL, 10);
                
                //creo nuovo file
                string new_file_name=(string)filename;
                string path=(string)constants::DIR_CLIENTS+username+"/"+new_file_name;
                
                if(!access(path.c_str(), 0)){
                    //se il file esiste già devo eliminarlo 
                    remove(path.c_str());                                
                }
                
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
                    msg_receive_len = receive_len(sd);
                    free(msg_to_receive);
                    msg_to_receive= (unsigned char*)malloc(msg_receive_len);
                    if(!msg_to_receive){
                        perror("Error during malloc()");
                        exit(-1);
                    }

                    //ricevo il messaggio di sessione
                    receive_obj(sd, msg_to_receive, msg_receive_len);
                    cout << "Received message <IV | AAD | tag | file content>" << endl;

                    //decifro il messaggio ricevuto
                    free(plaintext);
                    plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s);
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
                msg_receive_len = receive_len(sd);
                free(msg_to_receive);
                msg_to_receive= (unsigned char*)malloc(msg_receive_len);
                if(!msg_to_receive){
                    perror("Error during malloc()");
                    exit(-1);
                }
                receive_obj(sd, msg_to_receive, msg_receive_len);
                cout << "Received message <IV | AAD | tag | file content>" << endl;

                //decifro il messaggio ricevuto
                free(plaintext);
                plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s);
                ret = fwrite(plaintext, 1, dim_file-dim_write, clear_file);
                if(ret < pt_len) { 
                    perror("Error while writing the file"); 
                    exit(1); 
                }

                cout << "Download: success" << endl << endl;

                fclose(clear_file);
                free(plaintext);
                free(msg_to_receive);

            }

            break;

        case 3:
            //******************************************************************************
            //          DELETE
            //******************************************************************************

            //chiedo il file da eliminare
            cout << endl << "Please, type the file to delete: " << endl;
            memset(filename, 0, constants::DIM_FILENAME);
            if (!fgets(filename, constants::DIM_FILENAME, stdin))
            {
                perror("Error during the reading from stdin\n");
                exit(-1);
            }
            charPointer = strchr(filename, '\n');
            if (charPointer)
                *charPointer = '\0';
            
            // controllo che il filename non contenga caratteri speciali
            rett = control_white_list(filename);
            while (!rett)
            {
                cout << "Filename not valid" << endl;
                cout << "Please, insert a valid filename:" << endl;
                memset(filename, 0, constants::DIM_FILENAME);
                if (!fgets(filename, constants::DIM_FILENAME, stdin))
                {
                    perror("Error during the reading from stdin\n");
                    exit(-1);
                }
                charPointer = strchr(filename, '\n');
                if (charPointer)
                    *charPointer = '\0';

                // controllo che lo username non contenga caratteri speciali
                rett = control_white_list(filename);
            }

            // messaggio di richiesta: <IV | AAD | tag | delete_request | filename >
            array=(unsigned char*)malloc(constants::TYPE_CODE_SIZE);
            if(array == NULL){
                perror("Error during malloc()\n");
                exit(-1);
            }
            memcpy(array, constants::Delete_request, constants::TYPE_CODE_SIZE);

            sumControl(constants::TYPE_CODE_SIZE, sizeof(filename) );
            pt_len = constants::TYPE_CODE_SIZE + sizeof(filename) ;
            plaintext = (unsigned char *)malloc(pt_len);
            if (!plaintext)
            {
                perror("Error during malloc()");
                exit(-1);
            }
            memcpy(plaintext, array, constants::TYPE_CODE_SIZE);
            concatElements(plaintext, (unsigned char*)filename, constants::TYPE_CODE_SIZE, sizeof(filename));

            msg_to_send= symmetricEncryption(plaintext, pt_len, session_key, &msg_send_len, &count_c);

            send_int(sd, msg_send_len);
            send_obj(sd, msg_to_send, msg_send_len);
            free(msg_to_send);

            cout << "Sended message: <IV | AAD | tag | delete_request | filename >" << endl;

            msg_receive_len = receive_len(sd);
            msg_to_receive= (unsigned char*)malloc(msg_receive_len);
            if(!msg_to_receive){
                perror("Error during malloc()");
                exit(-1);
            }
            receive_obj(sd, msg_to_receive, msg_receive_len);

            // decifro il messaggio
            free(plaintext);
            plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s); 

            if(!strncmp((const char*)plaintext, constants::Not_acknowledgment, sizeof(constants::Not_acknowledgment)))
            {
                cout << "Received message <IV | AAD | tag | Not_Acknowledgement_type>" << endl;
                cout << "File doesn't exist" << endl;
                cout << "Delete request: unsuccess" << endl << endl;

                free(plaintext);
                free(msg_to_receive);

                continue;

            }else{
                cout << "Received message <IV | AAD | tag | Ask_confirmation_type>" << endl;

                rett=false;
                while(!rett){
                    cout << "Are you sure?(Yes/No)" << endl;
                    char resp[4];
                    memset(resp, 0, 4);
                    if (!fgets(resp, 4, stdin))
                    {
                        perror("Error during the reading from stdin\n");
                        exit(-1);
                    }
                    charPointer = strchr(resp, '\n');
                    if (charPointer)
                        *charPointer = '\0';

                    if(!strcmp(resp, "Yes")){
                        rett=true;
                        send_ack(sd,session_key, &count_c);

                        msg_receive_len = receive_len(sd);
                        free(msg_to_receive);
                        msg_to_receive= (unsigned char*)malloc(msg_receive_len);
                        if(!msg_to_receive){
                            perror("Error during malloc()");
                            exit(-1);
                        }
                        receive_obj(sd, msg_to_receive, msg_receive_len);

                        // decifro il messaggio
                        free(plaintext);
                        plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s); 

                        if(!strncmp((const char*)plaintext, constants::Acknowledgment, sizeof(constants::Acknowledgment))){
                            cout << "Delete request: success" << endl << endl;

                            free(plaintext);
                            free(msg_to_receive);  

                        }else{
                            cout << "Delete request: unsuccess" << endl << endl;

                            free(plaintext);
                            free(msg_to_receive);  
                        }

                    }else if(!strcmp(resp, "No")){
                        rett=true;
                        send_nack(sd, session_key, &count_c);
                        cout << "Delete request: unsuccess" << endl << endl;

                        free(plaintext);
                        free(msg_to_receive);                    

                    }else{
                        rett=false;

                    }
                }        

            }

            break;

        case 4:
            //******************************************************************************
            //          LIST
            //******************************************************************************

            // messaggio di richiesta: <IV | AAD | tag | delete_request | filename >
            array=(unsigned char*)malloc(constants::TYPE_CODE_SIZE);
            if(array == NULL){
                perror("Error during malloc()\n");
                exit(-1);
            }
            memcpy(array, constants::List_request, constants::TYPE_CODE_SIZE);

            pt_len = constants::TYPE_CODE_SIZE;
            plaintext = (unsigned char *)malloc(pt_len);
            if (!plaintext)
            {
                perror("Error during malloc()");
                exit(-1);
            }
            memcpy(plaintext, array, constants::TYPE_CODE_SIZE);
            
            msg_to_send= symmetricEncryption(plaintext, pt_len, session_key, &msg_send_len, &count_c);

            send_int(sd, msg_send_len);
            send_obj(sd, msg_to_send, msg_send_len);
            free(msg_to_send);

            cout << "Sended message: <IV | AAD | tag | List_request >" << endl;

            msg_receive_len = receive_len(sd);
            
            msg_to_receive= (unsigned char*)malloc(msg_receive_len);
            if(!msg_to_receive){
                perror("Error during malloc()");
                exit(-1);
            }
            receive_obj(sd, msg_to_receive, msg_receive_len);

            // decifro il messaggio
            free(plaintext);
            plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s); 
            
            if(!strncmp((const char*)plaintext, constants::List_file, sizeof(constants::List_file))){
                string list;
                extract_data_from_array((unsigned char*)list.c_str(), plaintext, constants::TYPE_CODE_SIZE, pt_len);
                
                cout << endl << "List:" << endl;
                char * array_list;
                array_list=strtok((char*)list.c_str(), ",");

                while(array_list!=NULL){
                    printf("%s\n", array_list);
                    array_list=strtok(NULL, ",");
                }
                cout << endl;
                cout << "list request: success" << endl << endl;

                free(plaintext);
                //mod
                free(msg_to_receive);
            }

            break;

        case 5:
            //******************************************************************************
            //          RENAME
            //******************************************************************************

            //chiedo il file da rinominare
            char old_filename[constants::DIM_FILENAME];
            char new_filename[constants::DIM_FILENAME];
            cout << endl << "Please, type the file to rename: " << endl;
            memset(old_filename, 0, constants::DIM_FILENAME);
            if (!fgets(old_filename, constants::DIM_FILENAME, stdin))
            {
                perror("Error during the reading from stdin\n");
                exit(-1);
            }
            charPointer = strchr(old_filename, '\n');
            if (charPointer)
                *charPointer = '\0';
            
            // controllo che il filename non contenga caratteri speciali
            rett = control_white_list(old_filename);
            while (!rett)
            {
                cout << "Filename not valid" << endl;
                cout << "Please, insert a valid filename:" << endl;
                memset(old_filename, 0, constants::DIM_FILENAME);
                if (!fgets(old_filename, constants::DIM_FILENAME, stdin))
                {
                    perror("Error during the reading from stdin\n");
                    exit(-1);
                }
                charPointer = strchr(old_filename, '\n');
                if (charPointer)
                    *charPointer = '\0';

                // controllo che il vecchio filename non contenga caratteri speciali
                rett = control_white_list(old_filename);
            }

            cout << endl << "Please, type the new filename: " << endl;
            memset(new_filename, 0, constants::DIM_FILENAME);
            if (!fgets(new_filename, constants::DIM_FILENAME, stdin))
            {
                perror("Error during the reading from stdin\n");
                exit(-1);
            }
            charPointer = strchr(new_filename, '\n');
            if (charPointer)
                *charPointer = '\0';
            
            // controllo che il nuovo filename non contenga caratteri speciali
            rett = control_white_list(new_filename);
            while (!rett)
            {
                cout << "Filename not valid" << endl;
                cout << "Please, insert a valid filename:" << endl;
                memset(new_filename, 0, constants::DIM_FILENAME);
                if (!fgets(new_filename, constants::DIM_FILENAME, stdin))
                {
                    perror("Error during the reading from stdin\n");
                    exit(-1);
                }
                charPointer = strchr(new_filename, '\n');
                if (charPointer)
                    *charPointer = '\0';

                // controllo che il nuovo filename non contenga caratteri speciali
                rett = control_white_list(new_filename);
            }

            // messaggio di richiesta: <IV | AAD | tag | rename_request | old_filename | new_filename >
            array=(unsigned char*)malloc(constants::TYPE_CODE_SIZE);
            if(array == NULL){
                perror("Error during malloc()\n");
                exit(-1);
            }
            memcpy(array, constants::Rename_request, constants::TYPE_CODE_SIZE);

            sumControl(constants::TYPE_CODE_SIZE, sizeof(old_filename) );
            sumControl(constants::TYPE_CODE_SIZE + sizeof(old_filename), sizeof(new_filename) );
            pt_len = constants::TYPE_CODE_SIZE + sizeof(old_filename) + sizeof(new_filename);
            plaintext = (unsigned char *)malloc(pt_len);
            if (!plaintext)
            {
                perror("Error during malloc()");
                exit(-1);
            }
            memcpy(plaintext, array, constants::TYPE_CODE_SIZE);
            concatElements(plaintext, (unsigned char*)old_filename, constants::TYPE_CODE_SIZE, sizeof(old_filename));
            concatElements(plaintext, (unsigned char*)new_filename, constants::TYPE_CODE_SIZE+sizeof(old_filename), sizeof(new_filename));

            msg_to_send= symmetricEncryption(plaintext, pt_len, session_key, &msg_send_len, &count_c);

            send_int(sd, msg_send_len);
            send_obj(sd, msg_to_send, msg_send_len);
            free(msg_to_send);

            cout << "Sended message: <IV | AAD | tag | rename_request | old_filename | new_filename >" << endl;

            //aspetto di ricevere l'ack
            msg_receive_len = receive_len(sd);
            msg_to_receive= (unsigned char*)malloc(msg_receive_len);
            if(!msg_to_receive){
                perror("Error during malloc()");
                exit(-1);
            }
            receive_obj(sd, msg_to_receive, msg_receive_len);

            // decifro il messaggio
            free(plaintext);
            plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s); 

            if(!strncmp((const char*)plaintext, constants::Not_acknowledgment, sizeof(constants::Not_acknowledgment)))
            {
                cout << "Received message <IV | AAD | tag | Not_Acknowledgement_type>" << endl;
                cout << "File doesn't exist" << endl;
                cout << "Rename request: unsuccess" << endl << endl;

                free(plaintext);
                free(msg_to_receive);

                continue;
            }else{
                cout << "Received message <IV | AAD | tag | Acknowledgement_type>" << endl;
                cout << "Rename request: success" << endl << endl;

                free(plaintext);
                free(msg_to_receive);
            }

            break;

        case 6:
            //******************************************************************************
            //          LOGOUT
            //******************************************************************************
            cout << endl << "Init Logout..." << endl;

            // messaggio di richiesta: <IV | AAD | tag | Logout_request>
            array=(unsigned char*)malloc(constants::TYPE_CODE_SIZE);
            if(array == NULL){
                perror("Error during malloc()\n");
                exit(-1);
            }
            
            memcpy(array, constants::Logout_request, constants::TYPE_CODE_SIZE);
            msg_to_send = symmetricEncryption(array, constants::TYPE_CODE_SIZE, session_key, &msg_send_len, &count_c);
             
            // mando la dimesione del messaggio
            send_int(sd, msg_send_len);

            // mando il messaggio
            send_obj(sd, msg_to_send, msg_send_len);

            cout  << "Sended message <IV | AAD | tag | Logout_request_type>" << endl;

            // ricevo l'ack
            msg_receive_len = receive_len(sd);
            msg_to_receive= (unsigned char*)malloc(msg_receive_len);
            if(!msg_to_receive){
                perror("Error during malloc()");
                exit(-1);
            }
            receive_obj(sd, msg_to_receive, msg_receive_len);

            cout << "Received message <IV | AAD | tag | Acknowledgement_type>" << endl;

            // decifro il messaggio
            plaintext = symmetricDecription(msg_to_receive, msg_receive_len, &pt_len, session_key, &count_s);
            
            if(!strncmp((const char*)plaintext, constants::Acknowledgment, sizeof(constants::Acknowledgment)))
            {
                cout << "Logout: success" << endl << endl;
                free(session_key);
                free(msg_to_send);
                free(plaintext);
                free(msg_to_receive);
                close(sd);
                return 0;
            }          

            cout << endl << "Logout: unsuccess" << endl << endl;
            break;

        default:
            cout << endl << "Insert a valid code operation" << endl;
            break;
        }
    }

    return 0;
}