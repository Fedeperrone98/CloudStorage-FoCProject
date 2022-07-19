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
#include<openssl/evp.h>
#include<openssl/pem.h>
#include<openssl/rand.h>
#include<openssl/x509.h>
#include<openssl/bio.h>
#include<openssl/err.h>
#include "util.cpp"

using namespace std;

void handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
}

//function that generate a nonce of NONCE_SIZE
void generateNonce(unsigned char* nonce){
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
EVP_PKEY* generateDHParams(){
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
EVP_PKEY*  getUserPbkey(string username){
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
EVP_PKEY* readPrivateKey(string username, string pwd, string who){
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
void loadCertificate(X509*& cert, string who){
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
void loadCRL(X509_CRL*& crl){
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
bool verifyCertificate(X509* cert_to_verify){
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

void getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey){
    pubkey = X509_get_pubkey(cert);
    if(!pubkey){
        handleErrors();
    }
}

//digital signature

//function that return the signature for a given plaintext and in signatureLen its length
void signatureFunction(unsigned char * plaintext, int dimpt, unsigned char* signature, int* signatureLen, EVP_PKEY* myPrivK){
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
bool verifySignature (unsigned char* signature,  unsigned char* unsigned_msg, int signature_size, int unsigned_size, EVP_PKEY* pubkey){
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

unsigned char* serializePublicKey(EVP_PKEY* privK, int* bufferLen){
	BIO* myBio;
	int ret;
	unsigned char* buffer;
	myBio = BIO_new(BIO_s_mem());
	if(myBio == NULL)
		return NULL;
	ret = PEM_write_bio_PUBKEY(myBio, privK);
	if(ret != 1)
		return NULL;
	buffer = NULL;
	*bufferLen = BIO_get_mem_data(myBio, &buffer);
	buffer = (unsigned char*) malloc(*bufferLen);
	if(!buffer){
		perror("malloc");
		exit(-1);
	}
	ret = BIO_read(myBio, (void*) buffer, *bufferLen);
	if(ret <= 0)
		return NULL;
	BIO_free(myBio);
	return buffer;
}

//Function that allocates and returns the deserialized public key. It returns NULL in case of error
EVP_PKEY* deserializePublicKey(unsigned char* buffer, int bufferLen){
	EVP_PKEY* pubKey;
	int ret;
	BIO* myBio;
	myBio = BIO_new(BIO_s_mem());
	if(myBio == NULL)
		return NULL;
	ret = BIO_write(myBio, buffer, bufferLen);
	if(ret <= 0)
		return NULL;
	pubKey = PEM_read_bio_PUBKEY(myBio, NULL, NULL, NULL);
	if(pubKey == NULL)
		return NULL;
	BIO_free(myBio);
	return pubKey;
}

//Function that takes a plaintext and allocates and returns a message formatted like 
    //{ <encrypted_key> | <IV> | <ciphertext> } 
    //in an asimmetric encryption and store its length in dimM. Exit in case of error
unsigned char* from_pt_to_DigEnv(unsigned char* pt, int pt_len, EVP_PKEY* pubkey, int* dimM){
	int ret;
	int dimB = 0;
	unsigned char* encrypted_key;
	unsigned char* iv;
	unsigned char* ciphertext;
	int encrypted_key_len, iv_len, cpt_len;
	unsigned char* buffer = NULL;
	unsigned char* message = NULL;
	int nc = 0;		//bytes encrypted at each chunk
	int nctot = 0;	//total encrypted bytes

	const EVP_CIPHER* cipher = EVP_aes_128_cbc();
	encrypted_key_len = EVP_PKEY_size(pubkey);
	iv_len = EVP_CIPHER_iv_length(cipher);
	encrypted_key = (unsigned char*) malloc(encrypted_key_len);
	iv = (unsigned char*) malloc(iv_len);

	sumControl(pt_len, EVP_CIPHER_block_size(cipher)); //sommo dimensione di un blocco per padding
	ciphertext = (unsigned char*) malloc(pt_len + EVP_CIPHER_block_size(cipher));

	if(!iv || !encrypted_key || !ciphertext)
	{
        perror("Error during malloc()");
		exit(-1);
    }

    //inizializzo contesto
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		handleErrors();

	ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, iv, &pubkey, 1);
	if(ret < 0)
		handleErrors();

	ret = EVP_SealUpdate(ctx, ciphertext, &nc, pt, pt_len);
	if(ret == 0)
		handleErrors();

	sumControl(nctot, nc);
	nctot += nc;

	ret = EVP_SealFinal(ctx, ciphertext + nctot, &nc);
	if(ret == 0)
		handleErrors();

	sumControl(nctot, nc);
	nctot += nc;
	cpt_len = nctot;

	EVP_CIPHER_CTX_free(ctx);
#pragma optimize("", off)
   	memset(pt, 0, pt_len);
#pragma optimize("", on)
   	free(pt);

	//message constitution
	sumControl(encrypted_key_len, iv_len);
	dimB = encrypted_key_len + iv_len;
	buffer = (unsigned char*) malloc(dimB);
	if(!buffer){
		perror("malloc");
		exit(-1);
	}
	concat2Elements(buffer, encrypted_key, iv, encrypted_key_len, iv_len);
	sumControl(dimB, cpt_len);
	*dimM = dimB + cpt_len;
	message = (unsigned char*) malloc(*dimM);
	if(!message){
		perror("malloc");
		exit(-1);
	}
	concat2Elements(message, buffer, ciphertext, dimB, cpt_len);
	free(iv);
	free(encrypted_key);
	free(ciphertext);
   	return message;
}

//takes the received message (formatted { <encrypted_key> | <IV> | <ciphertext> }) 
    //and allocates and returns the respective plaintext and stores its length in pt_len. 
    //Exit in case of error
unsigned char* from_DigEnv_to_PlainText(unsigned char* message, int messageLen, int* pt_len, EVP_PKEY* prvKey){
	int ret;
	unsigned char* pt = NULL;
	unsigned char* encrypted_key;
	unsigned char* iv;
	unsigned char* cpt;
	int encrypted_key_len, iv_len, cpt_len;
	int nd = 0; 	// bytes decrypted at each chunk
   	int ndtot = 0; 	// total decrypted bytes
	EVP_CIPHER_CTX* ctx;

	const EVP_CIPHER* cipher = EVP_aes_128_cbc(); 
	encrypted_key_len = EVP_PKEY_size(prvKey);
	iv_len = EVP_CIPHER_iv_length(cipher);
	sumControl(encrypted_key_len, iv_len);

	//check for correct format of the encrypted file
	if(messageLen < encrypted_key_len + iv_len)
	{
        perror("Error: invalid message");
        exit(-1);
    }

	encrypted_key = (unsigned char*) malloc(encrypted_key_len);
	iv = (unsigned char*) malloc(iv_len);
	cpt_len = messageLen - encrypted_key_len - iv_len;	//possible overflow already controlled
	cpt = (unsigned char*) malloc(cpt_len);
	pt = (unsigned char*) malloc(cpt_len);
	if(!iv || !encrypted_key || !cpt || !pt)
	{
        perror("Error during malloc()");
        exit(-1);
    }

    //estraggo dal messaggio ogni singola parte
	extract_data_from_array(encrypted_key, message, 0, encrypted_key_len);
	extract_data_from_array(iv, message, encrypted_key_len, encrypted_key_len + iv_len);
	extract_data_from_array(cpt, message, encrypted_key_len + iv_len, messageLen);
	
    //decryption
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		handleErrors();

	ret = EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, prvKey);
	if(ret == 0)
		handleErrors();

	ret = EVP_OpenUpdate(ctx, pt, &nd, cpt, cpt_len);
	if(ret == 0)
		handleErrors();
	sumControl(ndtot, nd);
	ndtot += nd;

	ret = EVP_OpenFinal(ctx, pt + ndtot, &nd);
	if(ret == 0)
		handleErrors();
	sumControl(ndtot, nd);
	ndtot += nd;
	*pt_len = ndtot;

	EVP_CIPHER_CTX_free(ctx);
	free(encrypted_key);
	free(iv);
	free(cpt);

	return pt;	
}

//Function that allocates and derive a symmetric key for aes_128_gcm by means of the DH shared secret, 
    //derived by using the two keys. Exit in case of error
unsigned char* symmetricKeyDerivation_for_aes_128_gcm(EVP_PKEY* privK, EVP_PKEY* pubK){
	unsigned char* secret;
	int secretLen;
	unsigned char* digest;
	int digestLen;
	unsigned char* key;
	int keyLen;
	EVP_MD_CTX* Hctx;
	EVP_PKEY_CTX* derive_ctx;
	int ret;

	const EVP_CIPHER* cipher = EVP_aes_128_gcm();;
	//secret derivation
	derive_ctx = EVP_PKEY_CTX_new(privK, NULL);
	if(derive_ctx == NULL)
		handleErrors();

	ret = EVP_PKEY_derive_init(derive_ctx);
	if(ret <= 0)
		handleErrors();

	ret = EVP_PKEY_derive_set_peer(derive_ctx, pubK);
	if(ret <= 0)
		handleErrors();

	EVP_PKEY_derive(derive_ctx, NULL, (size_t*)&secretLen);
	secret = (unsigned char*) malloc(secretLen);
	if(secret == NULL){
        perror("Error during malloc()\n");
        exit(-1);
    }

	EVP_PKEY_derive(derive_ctx, secret, (size_t*)&secretLen);
	EVP_PKEY_CTX_free(derive_ctx);

	//key derivation by hashing the shared secret
	Hctx = EVP_MD_CTX_new();
	digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
	if(!digest){
		perror("malloc");
		exit(-1);
	}

	ret = EVP_DigestInit(Hctx, EVP_sha256());
	if(ret != 1)
		handleErrors();

	ret = EVP_DigestUpdate(Hctx, secret, secretLen);
	if(ret != 1)
		handleErrors();

	ret = EVP_DigestFinal(Hctx, digest, (unsigned int*)&digestLen);
	if(ret != 1)
		handleErrors();

	EVP_MD_CTX_free(Hctx);

    // il digest sta su 256bit ma utilizzeremo solo i primi 128
	keyLen = EVP_CIPHER_key_length(cipher);
	key = (unsigned char*) malloc(keyLen);
	if(!key){
		perror("malloc");
		exit(-1);
	}

	memcpy(key, digest, keyLen);

#pragma optimize("", off);
	memset(digest, 0, digestLen);
	memset(secret, 0, secretLen);
#pragma optimize("", on);
	free(secret);
	free(digest);

	return key;
}

/*
//function that takes a plaintext and returns a buffer that has the format <IV | AAD | tag | ciphertext>
// Exit in case of error
unsigned char* symmetricEncryption(unsigned char *plaintext, int plaintext_len, unsigned char *key, int *totalLen, int* counter)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int outlen_tot=0;
	int ret = 0;
    int ciphertext_len = 0;
	unsigned char* outBuffer;
    const EVP_CIPHER* cipher = EVP_aes_128_gcm();

	unsigned char* tag = (unsigned char*) malloc(16);

	sumControl(plaintext_len, EVP_CIPHER_block_size(cipher));
	unsigned char* ciphertext = (unsigned char*) malloc(plaintext_len + /*EVP_CIPHER_block_size(cipher) 16);

	unsigned char* iv = (unsigned char*) malloc(constants::IV_LEN);

	char* AAD = (char*) malloc(constants::AAD_LEN);

	if(!tag | !ciphertext | !iv | !AAD){
		perror("malloc");
		exit(-1);
	}

	sprintf(AAD, "%d", *counter);
	IncControl(*counter);
	(*counter)++;

	ret = RAND_bytes(&iv[0], constants::IV_LEN);
	if (ret!=1)
		handleErrors();

	ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        handleErrors();

	ret = EVP_EncryptInit(ctx, cipher, key, iv);
    if(1 != ret)
        handleErrors();

	ret = EVP_EncryptUpdate(ctx, NULL, &len, (unsigned char *)AAD, constants::AAD_LEN);
    if(1 != ret)
        handleErrors();

    cout << "ok1" << endl;

    ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if(1 != ret)
        handleErrors();

    /*while(1){
        ret = EVP_EncryptUpdate(ctx, ciphertext+outlen_tot, &len, plaintext+outlen_tot, EVP_CIPHER_block_size(cipher));
        if(1 != ret)
            handleErrors();
        outlen_tot+=len;
        if(plaintext_len - outlen_tot < EVP_CIPHER_block_size(cipher))
            break;
    }

    cout << "ok2" << endl;
        
    //ciphertext_len = outlen_tot;
    ciphertext_len =len;
	ret = EVP_EncryptFinal(ctx, ciphertext + len, &len);
    if(1 != ret)
        handleErrors();

	sumControl(ciphertext_len, len);
    ciphertext_len += len;
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, constants::TAG_LEN, tag);
    if(1 != ret)
        handleErrors();
        
    EVP_CIPHER_CTX_free(ctx);

    // messaggio: <IV | AAD | tag | ciphertext>
	sumControl(ciphertext_len, constants::TAG_LEN);
	sumControl(ciphertext_len+constants::TAG_LEN, constants::IV_LEN);
	sumControl(ciphertext_len+constants::TAG_LEN+constants::IV_LEN, constants::AAD_LEN);
    *totalLen = ciphertext_len + constants::TAG_LEN + constants::IV_LEN + constants::AAD_LEN;
	outBuffer = (unsigned char*) malloc(*totalLen);
	if(!outBuffer){
		perror("malloc");
		exit(-1);
	}
	concatElements(outBuffer, iv, 0, constants::IV_LEN);
	concatElements(outBuffer, (unsigned char*)AAD, constants::IV_LEN, constants::AAD_LEN);
	concatElements(outBuffer, tag, constants::AAD_LEN + constants::IV_LEN, constants::TAG_LEN);
	concatElements(outBuffer, ciphertext, constants::AAD_LEN + constants::IV_LEN + constants::AAD_LEN, ciphertext_len);
	
    free(ciphertext);
	free(iv);
	free(tag);
	free(AAD);

	return outBuffer;
}*/

unsigned char* symmetricEncryption(unsigned char *plaintext, int plaintext_len, unsigned char *key, int *totalLen, int* counter)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
	int ret = 0;
    int ciphertext_len = 0;
	unsigned char* outBuffer;
	unsigned char* tag = (unsigned char*) malloc(constants::TAG_LEN);
	sumControl(plaintext_len, constants::TAG_LEN);
	unsigned char* ciphertext = (unsigned char*) malloc(plaintext_len + constants::TAG_LEN);
	unsigned char* iv = (unsigned char*) malloc(constants::IV_LEN);
	unsigned char* AAD = (unsigned char*) malloc(constants::AAD_LEN);
	if(!tag | !ciphertext | !iv | !AAD){
		perror("malloc");
		exit(-1);
	}
	sprintf((char*)AAD, "%d", *counter);
	IncControl(*counter);
	(*counter)++;
	ret = RAND_bytes(&iv[0], constants::IV_LEN);
	if (ret!=1)
		return NULL;
	ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        return NULL;
	ret = EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    if(1 != ret)
        return NULL;
	ret = EVP_EncryptUpdate(ctx, NULL, &len, AAD, constants::AAD_LEN);
    if(1 != ret)
        return NULL;
	ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if(1 != ret)
        return NULL;
    ciphertext_len = len;
	ret = EVP_EncryptFinal(ctx, ciphertext + len, &len);
    if(1 != ret)
        return NULL;
	sumControl(ciphertext_len, len);
    ciphertext_len += len;
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
    if(1 != ret)
        return NULL;
    EVP_CIPHER_CTX_free(ctx);
	sumControl(ciphertext_len, constants::TAG_LEN);
	sumControl(ciphertext_len+constants::TAG_LEN, constants::IV_LEN);
	sumControl(ciphertext_len+constants::TAG_LEN+constants::IV_LEN, constants::AAD_LEN);
    *totalLen = ciphertext_len + constants::TAG_LEN + constants::IV_LEN + constants::AAD_LEN;
	outBuffer = (unsigned char*) malloc(*totalLen);
	if(!outBuffer){
		perror("malloc");
		exit(-1);
	}
	concatElements(outBuffer, iv, 0, constants::IV_LEN);
	concatElements(outBuffer, AAD, constants::IV_LEN, constants::AAD_LEN);
	sumControl(constants::AAD_LEN, constants::IV_LEN);
	concatElements(outBuffer, tag, constants::AAD_LEN + constants::IV_LEN, constants::TAG_LEN);
	sumControl(constants::AAD_LEN+ constants::IV_LEN, constants::TAG_LEN);
	concatElements(outBuffer, ciphertext, constants::AAD_LEN + constants::IV_LEN + constants::TAG_LEN, ciphertext_len);
	free(ciphertext);
	free(iv);
	free(tag);
	free(AAD);
	return outBuffer;
}

/*
//function that takes a buffer formatted as <IV | AAD | tag | ciphertext> and 
//return the plaintext. exit in case of error
unsigned char* symmetricDecription(unsigned char *recv_buffer, int bufferLen, int *plaintext_len, unsigned char* key, int* expectedAAD)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER* cipher = EVP_aes_128_gcm();
    int len=0;
    int outlen_tot=0;
    int ret;
	unsigned char* iv;
	unsigned char* aad;
	int intAAD;
	unsigned char* tag;
	unsigned char* ciphertext;
	int ciphertext_len = bufferLen - constants::IV_LEN - constants::AAD_LEN - constants::TAG_LEN;
	unsigned char* plaintext;
	unsigned char* buffer = (unsigned char*) malloc(ciphertext_len);
    //unsigned char* buffer = (unsigned char*) malloc(1);

	//extract informations
	ciphertext = (unsigned char*) malloc(ciphertext_len);
	iv = (unsigned char*) malloc(constants::IV_LEN);
	aad = (unsigned char*) malloc(constants::AAD_LEN);
	tag = (unsigned char*) malloc(constants::TAG_LEN);
	if(!aad | !iv | !tag | !ciphertext){
		perror("Error during malloc()");
		exit(-1);
	}

    cout << " ok1" << endl;

    //<IV | AAD | tag | ciphertext>

	extract_data_from_array(iv, recv_buffer, 0, constants::IV_LEN);
	
    sumControl(constants::AAD_LEN, constants::IV_LEN);
	sumControl(constants::IV_LEN+constants::AAD_LEN, constants::TAG_LEN);
	
    extract_data_from_array(aad, recv_buffer, constants::IV_LEN, constants::IV_LEN + constants::AAD_LEN);
	extract_data_from_array(tag, recv_buffer, constants::IV_LEN + constants::AAD_LEN, constants::IV_LEN + constants::AAD_LEN + constants::TAG_LEN);
	extract_data_from_array(ciphertext, recv_buffer, constants::IV_LEN + constants::AAD_LEN + constants::TAG_LEN, bufferLen);
	
    cout << " ok2" << endl;
    intAAD = atoi((const char*)aad);
	if(intAAD != *expectedAAD){
		perror("The two counters are different");
		exit(-1);
	}
	IncControl(*expectedAAD);
	(*expectedAAD)++;
    cout << " ok3" << endl;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    ret= EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    if(ret!=1)
        handleErrors();

    ret= EVP_DecryptUpdate(ctx, NULL, &len, aad, constants::AAD_LEN);
    if(ret!=1)
        handleErrors();
    cout << " ok4" << endl;
    ret=EVP_DecryptUpdate(ctx, buffer, &len, ciphertext, ciphertext_len);
    if(ret!=1)
        handleErrors();
    outlen_tot=len;
    cout << " ok5" << endl;
    /*while(1){
        ret=EVP_DecryptUpdate(ctx, buffer+outlen_tot, &len, ciphertext+outlen_tot, EVP_CIPHER_block_size(cipher));
        if(ret!=1)
            handleErrors();
        outlen_tot+=len;
        if(ciphertext_len - outlen_tot < EVP_CIPHER_block_size(cipher))
            break;
    }
    *plaintext_len = outlen_tot;
     cout << " ok5.1" << endl;
    ret=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, constants::TAG_LEN, tag);
    if(ret!=1)
        handleErrors();
     cout << " ok5.2" << endl;
    ret = EVP_DecryptFinal(ctx, buffer + len, &len);
    if(ret!=1)
        handleErrors();
     cout << " ok5.3" << endl;
	EVP_CIPHER_CTX_free(ctx);

    cout << " ok6" << endl;
	sumControl(*plaintext_len, len);
	*plaintext_len += len;
	plaintext = (unsigned char*) malloc((*plaintext_len));
	if(!plaintext){
		perror("Error during malloc()");
		exit(-1);
	}
	memcpy(plaintext, buffer, *plaintext_len);
    cout << " ok7" << endl;
	free(tag);
	free(iv);
	free(aad);
	free(buffer);
	free(ciphertext);
    cout << " fine decription" << endl;
	return plaintext;
}*/

unsigned char* symmetricDecription(unsigned char *recv_buffer, int bufferLen, int *plaintext_len, unsigned char* key, int* expectedAAD)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret;
	unsigned char* iv;
	unsigned char* aad;
	int intAAD;
	unsigned char* tag;
	unsigned char* ciphertext;
	int ciphertext_len = bufferLen - constants::IV_LEN- constants::AAD_LEN - constants::TAG_LEN;
	unsigned char* plaintext;
	unsigned char* buffer = (unsigned char*) malloc(ciphertext_len);
	//extract informations
	ciphertext = (unsigned char*) malloc(ciphertext_len);
	iv = (unsigned char*) malloc(constants::IV_LEN);
	aad = (unsigned char*) malloc(constants::AAD_LEN);
	tag = (unsigned char*) malloc(constants::TAG_LEN);
	if(!aad | !iv | !tag | !ciphertext){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(iv, recv_buffer, 0, constants::IV_LEN);
	sumControl(constants::AAD_LEN, constants::IV_LEN);
	sumControl(constants::IV_LEN+constants::AAD_LEN, constants::TAG_LEN);
	extract_data_from_array(aad, recv_buffer, constants::IV_LEN, constants::IV_LEN + constants::AAD_LEN);
	extract_data_from_array(tag, recv_buffer, constants::IV_LEN + constants::AAD_LEN, constants::IV_LEN + constants::AAD_LEN + constants::TAG_LEN);
	extract_data_from_array(ciphertext, recv_buffer, constants::IV_LEN + constants::AAD_LEN + constants::TAG_LEN, bufferLen);
	intAAD = atoi((const char*)aad);
	if(intAAD != *expectedAAD){
		perror("The two counters are different");
		exit(-1);
	}
	IncControl(*expectedAAD);
	(*expectedAAD)++;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return NULL;
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return NULL;
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, constants::AAD_LEN))
        return NULL;
    if(!EVP_DecryptUpdate(ctx, buffer, &len, ciphertext, ciphertext_len))
        return NULL;
    *plaintext_len = len;
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        return NULL;
    ret = EVP_DecryptFinal(ctx, buffer + len, &len);

	EVP_CIPHER_CTX_free(ctx);

    if(ret < 0)
		return NULL;
	sumControl(*plaintext_len, len);
	*plaintext_len += len;
	plaintext = (unsigned char*) malloc((*plaintext_len));
	if(!plaintext){
		perror("Error during malloc()");
		exit(-1);
	}
	memcpy(plaintext, buffer, *plaintext_len);
	free(tag);
	free(iv);
	free(aad);
	free(buffer);
	free(ciphertext);
	return plaintext;
}


