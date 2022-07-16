#include "include/crypto.h"
#include "util.cpp"

using namespace std;

void CryptoOperation::handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
}

//function that generate a nonce of NONCE_SIZE
void CryptoOperation::generateNonce(unsigned char* nonce){
    if(RAND_poll() != 1){
        handleErrors();
    }

    if(RAND_bytes(nonce, constants::NONCE_SIZE)!=1){
        handleErrors();
    }
}

//key 

//function that return Diffie-Hellman low level parameters
static DH *get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0x86, 0x97, 0x93, 0xE0, 0x6A, 0xC5, 0x66, 0x94, 0xF9, 0x41,
        0x2E, 0x0C, 0xD9, 0xA6, 0x1A, 0xC6, 0xE5, 0x5A, 0xCA, 0xB7,
        0xA8, 0xDF, 0x01, 0x2F, 0xE3, 0x2D, 0xF2, 0xC3, 0x13, 0x0A,
        0x8C, 0x36, 0x87, 0x1B, 0x08, 0x2A, 0x68, 0xB8, 0xCD, 0x31,
        0xFB, 0x28, 0x0B, 0xD1, 0x86, 0x98, 0x62, 0xE1, 0x73, 0xFA,
        0xEF, 0x45, 0x42, 0x36, 0xCC, 0x92, 0x79, 0x7C, 0xD6, 0x6D,
        0x91, 0x0F, 0x60, 0x82, 0x93, 0xB5, 0x97, 0x13, 0xD5, 0x5E,
        0x7A, 0x82, 0xE5, 0x28, 0xB8, 0xB9, 0x97, 0x58, 0x81, 0x66,
        0x47, 0x2C, 0x4A, 0x27, 0x8B, 0xD7, 0xAC, 0x4B, 0xF3, 0xF7,
        0x99, 0x7D, 0xDD, 0x92, 0x21, 0x70, 0xBD, 0xF7, 0x30, 0xEE,
        0xD6, 0xFC, 0x29, 0x32, 0xC5, 0xB4, 0x05, 0x78, 0x51, 0x3F,
        0xCF, 0x41, 0xE9, 0x73, 0x4B, 0x3B, 0x99, 0x15, 0x68, 0xF9,
        0x8A, 0xB6, 0x6D, 0x83, 0x08, 0xFF, 0xF1, 0x8A, 0x96, 0xC1,
        0x13, 0x86, 0xB1, 0x04, 0x6B, 0x9A, 0x52, 0x3D, 0xEF, 0x0A,
        0x27, 0x5F, 0x92, 0xB1, 0x6B, 0x51, 0x65, 0xB9, 0x13, 0x8F,
        0x24, 0x18, 0x9A, 0x32, 0x5F, 0x47, 0xA8, 0xF4, 0x11, 0xEB,
        0xA2, 0x8B, 0x61, 0x3A, 0xD9, 0x80, 0xF5, 0x2E, 0x63, 0x21,
        0x44, 0xA3, 0x18, 0x19, 0x43, 0x01, 0x5B, 0x0C, 0x94, 0x2E,
        0x77, 0xD7, 0x93, 0x5D, 0x5C, 0x77, 0xBA, 0x0F, 0x5A, 0xBD,
        0x4E, 0x10, 0x32, 0xE0, 0xFA, 0xC1, 0xB9, 0x0A, 0xB1, 0x43,
        0xD2, 0xBD, 0x76, 0xBC, 0x4D, 0xF8, 0xCC, 0xD3, 0xEE, 0xCC,
        0x3A, 0xB2, 0x08, 0x9B, 0x24, 0x5B, 0x05, 0x8A, 0xA5, 0x0A,
        0x9E, 0x0E, 0xE5, 0xB2, 0x9C, 0x01, 0x38, 0xD3, 0xE1, 0xD7,
        0x0C, 0xAA, 0x09, 0xDA, 0xE3, 0x56, 0x1A, 0x26, 0xBC, 0x0B,
        0x71, 0xBD, 0xA7, 0xD5, 0x5E, 0xF8, 0xB1, 0x61, 0x8A, 0xC0,
        0x51, 0xFA, 0xDD, 0xE8, 0x55, 0x73
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

//function that allocates and generates Diffie-Hellman private key
EVP_PKEY* CryptoOperation::generateDHParams(){
    int ret;
    EVP_PKEY* DHparams;
    EVP_PKEY_CTX* DHctx;
    EVP_PKEY* dhPrivateKey;

    DHparams= EVP_PKEY_new();
    if(DHparams == NULL){
        handleErrors();
    }

    DH* temp = get_dh2048();

    ret= EVP_PKEY_set1_DH(DHparams, temp);
    if(ret!=1){
        handleErrors();
    }

    DH_free(temp);

    DHctx= EVP_PKEY_CTX_new(DHparams, NULL);
    if(DHctx==NULL){
        handleErrors();
    }

    ret= EVP_PKEY_keygen_init(DHctx);
    if(ret!=1){
        handleErrors();
    }

    dhPrivateKey=NULL;
    ret= EVP_PKEY_keygen(DHctx, &dhPrivateKey);
    if(ret!=1){
        handleErrors();
    }

    EVP_PKEY_CTX_free(DHctx);
    EVP_PKEY_free(DHparams);

    return dhPrivateKey;
}

//function that return user public key
EVP_PKEY*  CryptoOperation::getUserPbkey(string username){
    EVP_PKEY* pubkey;

    string path = constants::DIR_CLIENTS + username + "/" + username + constants::SUFFIX_PUBKEY;
    FILE* file = fopen(path.c_str(), "r");
    if(!file){
        perror("cannot open the user pubKey file");
        exit(-1);
    }

    pubkey= PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubkey){
        fclose(file);
        handleErrors();
    }

    fclose(file);

    return pubkey;
}

//function that return user private key or the server private key
EVP_PKEY* CryptoOperation::readPrivateKey(string username, string pwd, string who){
    EVP_PKEY* prvkey;
    string path;

    if(who == "server" ){
        path = constants::DIR_SERVER + username + constants::SUFFIX_PRVKEY;
    }else{
        path = constants::DIR_CLIENTS + username + "/" + username + constants::SUFFIX_PRVKEY;
    }

    FILE* file = fopen(path.c_str(), "r");
    if(!file){
        perror("cannot open the user prvKey file");
        exit(-1);
    }

    prvkey= PEM_read_PrivateKey(file, NULL, NULL, (char*)pwd.c_str());
    if(!prvkey){
        fclose(file);
        handleErrors();
    }

    fclose(file);

    return prvkey;
}

//certificate

//function that load the certificate of the server or of the CA
void CryptoOperation::loadCertificate(X509*& cert, string who){
    string path;

    if(who=="server"){
        path= constants::NAME_SERVER_CERT;
    }else{
        path= constants::NAME_CA_CERT;
    }

    FILE* file= fopen(path.c_str(), "r");
    if(!file){
        perror("cannot open the cert file");
        exit(-1);
    }

    cert= PEM_read_X509(file, NULL, NULL, NULL);
    if(!cert){
        fclose(file);
        handleErrors();
    }

    fclose(file);
}

//function that load the crl of the CA
void CryptoOperation::loadCRL(X509_CRL*& crl){
    string path= constants::NAME_CA_CRL;

    FILE* file = fopen(path.c_str(), "r");
    if(!file){
        perror("cannot open the crl file");
        exit(-1);
    }

    crl= PEM_read_X509_CRL(file, NULL, NULL, NULL);
    if(!crl){
        fclose(file);
        handleErrors();
    }

    fclose(file);
}

//function that verify the certificate and returns true if the certificate is verified
bool CryptoOperation::verifyCertificate(X509* cert_to_verify){
    int ret;

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if(!ctx){
        handleErrors();
    }

    X509* ca_cert;
    X509_STORE* store;
    X509_CRL* crl;

    loadCertificate(ca_cert, "ca");
    loadCRL(crl);

    store= X509_STORE_new();
    if(!store){
        handleErrors();
    }

    try{
        ret= X509_STORE_add_cert(store, ca_cert);
        if(ret<1){
            handleErrors();
        }

        ret= X509_STORE_add_crl(store, crl);
        if(ret<1){
            handleErrors();
        }

        ret= X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
        if(ret<1){
            handleErrors();
        }

        ret=X509_STORE_CTX_init(ctx, store, cert_to_verify, NULL);
        if(ret<1){
            handleErrors();
        }

    }catch(const exception& e){
        X509_STORE_free(store);
        throw;
    }

    ret= X509_verify_cert(ctx);
    if(ret!=1){
        int err = X509_STORE_CTX_get_error(ctx);
        cerr << X509_verify_cert_error_string(err) << endl;
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return false;
    }

    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);
    return true;
}

void CryptoOperation::getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey){
    pubkey = X509_get_pubkey(cert);
    if(!pubkey){
        handleErrors();
    }
}

unsigned int CryptoOperation::serializeCertificate(X509* cert, unsigned char* cert_buf){
    int cert_size = i2d_X509(cert,&cert_buf);
    if(cert_size < 0) {
        handleErrors();
    }

    return cert_size;
}

void CryptoOperation::deserializeCertificate(int cert_len,unsigned char* cert_buff, X509*& buff){

    cout << "cert_len" << cert_len << endl;
    buff = d2i_X509(NULL,(const unsigned char**)&cert_buff,cert_len);
    if(!buff) {
        handleErrors();
    }
}

//digital signature

//function that return the signature for a given plaintext and in signatureLen its length
void CryptoOperation::signatureFunction(unsigned char * plaintext, int dimpt, unsigned char* signature, int* signatureLen, EVP_PKEY* myPrivK){
    int ret;

    EVP_MD_CTX* signCtx= EVP_MD_CTX_new();
    if(!signCtx){
        handleErrors();
    }

    ret= EVP_SignInit(signCtx, EVP_sha256());
    if(ret==0){
        handleErrors();
    }

    ret= EVP_SignUpdate(signCtx, plaintext, dimpt);
    if(ret==0){
        handleErrors();
    }

    ret = EVP_SignFinal(signCtx, (unsigned char*)signature, (unsigned int*)signatureLen, myPrivK);
    if(ret==0){
        handleErrors();
    }

    EVP_MD_CTX_free(signCtx);

    return;
}

//function wthat verifies the signature
bool CryptoOperation::verifySignature (unsigned char* signature,  unsigned char* unsigned_msg, int signature_size, int unsigned_size, EVP_PKEY* pubkey){
    int ret;

    EVP_MD_CTX* signCtx= EVP_MD_CTX_new();
    if(!signCtx){
        handleErrors();
    }

    ret= EVP_VerifyInit(signCtx, EVP_sha256());
    if(ret!=1){
        handleErrors();
    }

    ret= EVP_VerifyUpdate(signCtx, unsigned_msg, unsigned_size);
    if(ret!=1){
        handleErrors();
    }

    ret= EVP_VerifyFinal(signCtx, signature, signature_size, pubkey);
    if(ret!=1){
        EVP_MD_CTX_free(signCtx);
        return false;
    }
    
    EVP_MD_CTX_free(signCtx);
    return true;
}