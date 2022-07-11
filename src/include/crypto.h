#include <iostream>
#include <string>
#include <array>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "constants.h"

using namespace std;

class CryptoOperation {

    public:
        void handleErrors(void);

        void generateNonce(unsigned char* nonce);

        //key
        EVP_PKEY* generateDHParams();
        EVP_PKEY*  getUserPbkey(string username);
        EVP_PKEY* readPrivateKey(string username, string pwd, string who);

        //certificate
        void loadCertificate(X509*& cert, string path);
        void loadCRL(X509_CRL*& crl);
        bool verifyCertificate(X509* cert_to_verify);
        void getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey);

        //digital signature
        void signatureFunction(unsigned char * plaintext, int dimpt, unsigned char* signature, int* signatureLen, EVP_PKEY* myPrivK);
        bool verifySignature (unsigned char* signature,  unsigned char* unsigned_msg, int signature_size, int unsigned_size, EVP_PKEY* pubkey);
};