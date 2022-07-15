#ifndef CONSTANTS_H
#define CONSTANTS_H
namespace constants
{
    constexpr unsigned int MAX_CLIENTS = 10;
    constexpr unsigned int SERVER_PORT = 4242;
    constexpr const char* LOCAL_HOST ="127.0.0.1";

    constexpr unsigned int NONCE_SIZE = 16;
    constexpr unsigned int TAG_LEN = 16;
    constexpr unsigned int IV_LEN = 12;
    constexpr unsigned int AAD_LEN = 12;

    constexpr const char* DIR_CLIENTS ="./data/clients/";
    constexpr unsigned int DIM_DIR_CLIENTS = 16;
    constexpr const char* DIR_SERVER ="./data/server/";
    constexpr unsigned int DIM_DIR_SERVER = 15;

    constexpr const char* SUFFIX_PUBKEY ="_pubk.pem";
    constexpr unsigned int DIM_SUFFIX_PUBKEY = 10;
    constexpr const char* SUFFIX_PRVKEY ="_prvk.pem";
    constexpr unsigned int DIM_SUFFIX_PRVKEY = 10;

    constexpr const char* NAME_SERVER_CERT = "./data/server/server_cert.pem";
    constexpr unsigned int DIM_NAME_SERVER_CERT = 30;
    constexpr const char* NAME_CA_CERT = "./data/server/FoundationsOfCybersecurity_cert.pem";
    constexpr unsigned int DIM_NAME_CA_CERT = 50;
    constexpr const char* NAME_CA_CRL = "./data/server/FoundationsOfCybersecurity_crl.pem";
    constexpr unsigned int DIM_NAME_CA_CRL = 49;

    //TYPE CODE
    constexpr const char Update_request = 0x01;
    constexpr const char Acknowledgment = 0x02;
    constexpr const char Not_acknowledgment = 0x03;
    constexpr const char File_content = 0x04;
    constexpr const char Download_request = 0x05;
    constexpr const char Size = 0x06;
    constexpr const char Delete_request = 0x07;
    constexpr const char Ask_confirmation = 0x08;
    constexpr const char List_request = 0x09;
    constexpr const char List_file = 0x10;
    constexpr const char Rename_request = 0x11;
    constexpr const char Logout_request = 0x12;
}
#endif