#ifndef CONSTANTS_H
#define CONSTANTS_H
namespace constants
{
    constexpr unsigned int MAX_CLIENTS = 10;
    constexpr unsigned int SERVER_PORT = 4242;
    constexpr const char* LOCAL_HOST ="127.0.0.1";

    constexpr unsigned int DIM_USERNAME = 30;
    constexpr unsigned int DIM_FILENAME = 30;
    constexpr unsigned int TOT_USERS = 4;

    constexpr unsigned int MAX_READ = 1000000;

    constexpr unsigned int DIM_PASSWORD = 30;

    constexpr unsigned int NONCE_SIZE = 16;
    constexpr unsigned int TAG_LEN = 16;
    constexpr unsigned int IV_LEN = 12;
    constexpr unsigned int AAD_LEN = 12;

    constexpr const char* DIR_CLIENTS ="../data/clients/";
    constexpr unsigned int DIM_DIR_CLIENTS = 16;
    constexpr const char* DIR_SERVER ="../data/server/";
    constexpr unsigned int DIM_DIR_SERVER = 15;

    constexpr const char* SUFFIX_PUBKEY ="_pubk.pem";
    constexpr unsigned int DIM_SUFFIX_PUBKEY = 10;
    constexpr const char* SUFFIX_PRVKEY ="_prvk.pem";
    constexpr unsigned int DIM_SUFFIX_PRVKEY = 10;

    constexpr const char* NAME_SERVER_CERT = "../data/server/server_cert.pem";
    constexpr unsigned int DIM_NAME_SERVER_CERT = 30;
    constexpr const char* NAME_CA_CERT = "../data/server/FoundationsOfCybersecurity_cert.pem";
    constexpr unsigned int DIM_NAME_CA_CERT = 50;
    constexpr const char* NAME_CA_CRL = "../data/server/FoundationsOfCybersecurity_crl.pem";
    constexpr unsigned int DIM_NAME_CA_CRL = 49;

    //TYPE CODE
    constexpr const int TYPE_CODE_SIZE= 4;
    constexpr const char* Upload_request = "upl";
    constexpr const char* Acknowledgment = "ack";
    constexpr const char* Not_acknowledgment = "not";
    constexpr const char* Download_request = "dow";
    constexpr const char* Size = "siz";
    constexpr const char* Delete_request = "del";
    constexpr const char* Ask_confirmation = "ask";
    constexpr const char* List_request = "lre";
    constexpr const char* List_file = "lfi";
    constexpr const char* Rename_request = "ren";
    constexpr const char* Logout_request = "log";
}
#endif