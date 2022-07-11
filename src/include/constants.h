#ifndef CONSTANTS_H
#define CONSTANTS_H
namespace constants
{
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
}
#endif