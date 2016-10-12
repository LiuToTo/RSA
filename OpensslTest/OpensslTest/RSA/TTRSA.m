//
//  RSA.m
//  OpensslTest
//
//  Created by 刘ToTo on 16/10/12.
//  Copyright © 2016年 com.365ime. All rights reserved.
//

#import "TTRSA.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#import "QSStrings.h"
#import <CommonCrypto/CommonCrypto.h>
#import "NSString+Hex.h"

#define kSecPublicKeyTag @"com.365ime.rsa_public_key"
#define kSecPrivateKeyTag @"com.365ime.rsa_private_key"
#define kPublicKeyBegin @"-----BEGIN PUBLIC KEY-----"
#define kPublicKeyEnd @"-----END PUBLIC KEY-----"
#define kPrivateKeyBegin @"-----BEGIN RSA PRIVATE KEY-----"
#define kPrivateKeyEnd @"-----END RSA PRIVATE KEY-----"

typedef enum : NSUInteger {
    TTRSAKeyTypePublic = 1,
    TTRSAKeyTypePrivate = 2,
} TTRSAKeyType;

@interface TTRSA (){
    RSA *_keyPair;
    int _bits;
}

@end
@implementation TTRSA{
    unsigned char *pri_key;
    unsigned char *pub_key;
    SecKeyRef publicSeckeyRef;
    SecKeyRef privateSecKeyRef;
}

#pragma mark - initialization
- (instancetype)initWithBits:(int)bits{
    if (self = [super init]) {
        _bits = bits;
        [self generateRsaKeypair:_bits];
    }
    return self;
}

- (instancetype)initWithRSAKeyPair:(NSData *)rsaKeyPaireData{
    if (self = [super init]) {
        _rsa_keyPaire_data = rsaKeyPaireData;
    }
    return self;
}

- (instancetype)init{
    if (self = [super init]) {
        [self generateRsaKeypair:1024];

    }
    return self;
}

#pragma mark - generate
- (void)generateRsaKeypair:(int)bits{
    
    int ret;
    unsigned int e = RSA_3;
    BIGNUM *bne;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    _keyPair = RSA_new();
    
    // generate key pair
    int result = RSA_generate_key_ex(_keyPair, bits,bne, NULL);
    if (result !=1) {
    
    }
    
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
    
    PEM_write_bio_RSAPrivateKey(pri, _keyPair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, _keyPair);
    
    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);
    
    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);
    
    BIO_read(pri, pri_key, (int) pri_len);
    BIO_read(pub, pub_key, (int) pub_len);
    
    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    // generate keypair
    printf("\n%s\n%s\n", pri_key, pub_key);
    
    
    const char* priv_k = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEApnHiE8ao2ZtleP0KJLFSPkOVhMUlFNCFKFEEt17KZFjUM3Zh\nhPlahxq038dejBICFDsEHvXZ8T+8UKBDQI6/DAUgparqUqE4gqSiQeGFDhrY8cBi\n7lAD/h7u4FI1+nEbHf7JkfhDz57HZhgf/l6rKNEr7sqkdCJKp2XFqJVzfDs3vnQI\n0NCiVQeJysjTXRzH8VMNv9exV9ZrSasjA57VNaUN9fZnvewqUEvTTzFwXVeV0FDX\nbYUq0cFGMjFB+gCFpaOMSQpQayZEWsdpMTMYTt84VHVZ+aVtBYxdmXk/hilodQsN\niK3dmM54lwvo+8N2M1jQyOlP+QWPWilzPI+h4wIDAQABAoIBAGxQ5lgKSy25o/J1\ncVlpj+T3JGFPzo7aGB2hg9k1Na7R495Npq7bet87MQQEAXJT8chqk4b2ZUtLN+ic\nMsfbXVacK5/EN1NomZbjPrhy45zHOfExSvBdYAvK45dVyMzfOE9v1ItKrg55/Ldi\n8cceonIglV+DvjvZaQ3A/D12bL4l2qlZICTpgjK3yGshEWrdEwIk36LRiefPLCqW\nYE/4TTOHkd80PDX2QmBUtYmBsq0nrUQqr1wFbaiDC3G3wctarNSUJds6Z4KILFOq\nOUZfnmL1cEQfyr7Q9i2ZLDqR+b4PAluE0BEenn0HsaVD4ug17gD/YDHUSz0LhmCq\npu6vB7kCgYEA0uhWrSYc+qjgR+dlWSlaurnEIQMh7oV6y/RXvmwc9aOBHQDjvP7+\ntFcxizC4uMNR6HkPwkWN7wuCnbbKWZqvjuY/jj2jtAqRrBgpRNV3q3UD0Y2fGV2Q\ndiSdXeQfJKV490AKMHlyZ+mHsOJjcODW9F6IuAavVw8X+/pDSnS4oPUCgYEAygf0\nYEtj8Pk1FhawXCLaINyiI9kKam1RTeSdI9vj06zJa92VpQxbWKdDptGmfCwDM5lw\nG+SF6hxmdHKqyvEEjRWXqL2vYWvWRlntl15NRN744mN1nPdelDHF4Hqg4OAe1+sc\nnAdrPelkNlTtYGy+pZm9edFR3J89kwNoFeOHkHcCgYBSKmn6Mur/TGN0H9YAEnhi\nXpTmN440mpPoeVzltsDhgb1/SyVuL/mS0JVgoK6WbKGwa9mT2f0dr+JHBzt2BSl4\nBoOkKqdoMOXnodISGwfwKDpAnWfqPeVV4ZXdSk5HvJ+P08ckc2v6x6QxaUFMbIvR\n0DJ7Xz9YL20soactjqOPMQKBgQCv48cFgv1q0Xw/U9eND6a6j3v2G8Kur6fmWc/Z\nZVpvcnIWH99lx2FLyKvkc4gveR38cWyiTA2uqbUlUqORdc5Rimf0N9iVx43QyABL\nFYXOHRWv+4ls9Ax6lu7ApeKkhVs0/nN1AByE1Uoy5zOXDHXatQO6J9vOaTDxajjX\nPbVLtwKBgDBMlTjPXOJbdiCVe8y+F4MTuykrveGf9MF7MqQU3Mtsaf0w5Jq33gAf\nKhlSpREs3YRXjxEahAoqmPQQGPEpmCpKJaFVKJrgGikmso34sS87IgLCGwwO/H5C\nKPTWKBwkLR7FzYgZdgHQQTpl+2wEe12/IYbMhewRY7mdlrOwXdQT\n-----END RSA PRIVATE KEY-----";
    
    const char* pub_k = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApnHiE8ao2ZtleP0KJLFS\nPkOVhMUlFNCFKFEEt17KZFjUM3ZhhPlahxq038dejBICFDsEHvXZ8T+8UKBDQI6/\nDAUgparqUqE4gqSiQeGFDhrY8cBi7lAD/h7u4FI1+nEbHf7JkfhDz57HZhgf/l6r\nKNEr7sqkdCJKp2XFqJVzfDs3vnQI0NCiVQeJysjTXRzH8VMNv9exV9ZrSasjA57V\nNaUN9fZnvewqUEvTTzFwXVeV0FDXbYUq0cFGMjFB+gCFpaOMSQpQayZEWsdpMTMY\nTt84VHVZ+aVtBYxdmXk/hilodQsNiK3dmM54lwvo+8N2M1jQyOlP+QWPWilzPI+h\n4wIDAQAB\n-----END PUBLIC KEY-----";
    
    
    
    NSString *pubk = [[NSString alloc] initWithCString:(const char*)pub_k encoding:NSUTF8StringEncoding];
    NSString *prik = [[NSString alloc] initWithCString:(const char*)priv_k encoding:NSUTF8StringEncoding];
    
    publicSeckeyRef = [self saveRsaKey:pubk rsaKeyType:TTRSAKeyTypePublic];
    privateSecKeyRef = [self saveRsaKey:prik rsaKeyType:TTRSAKeyTypePrivate];
    
    // sha1
    NSString *str = @"hello";
    NSString *sha1 = [pubk sha1ByHex];
    
    // sign and verify
    NSData *cipherData = [self secPrivateSignBytesSHA1: [sha1 hexToBytes] privateKey:privateSecKeyRef];
    
    // base64
    NSString *cipherText = [cipherData base64EncodedStringWithOptions:0];
    
    BOOL isVerified =[self secPublicVerifyBytesSHA1:cipherData plainData:[sha1 hexToBytes] publicKey:publicSeckeyRef];
    
    NSLog(@"%d",isVerified);
    
//    [self secEncryptByPublicKey:publicSeckeyRef plainText:@"123"];
    NSString *ct = [self rsaEncryptString:@"liuxu123."];
    NSString *pt = [self rsaDecryptString:ct];
}


- (SecKeyRef)saveRsaKey:(NSString *)keyStr rsaKeyType:(TTRSAKeyType)keyType{
    
    NSString * tag = [self tagString4SecKey:keyType];
    
    NSString *s_key = [NSString string];
    NSArray  *a_key = [keyStr componentsSeparatedByString:@"\n"];
    BOOL     f_key  = FALSE;
    
    for (NSString *a_line in a_key) {
        if ([a_line isEqualToString:[self symbol4Begin:keyType]]) {
            f_key = TRUE;
        }
        else if ([a_line isEqualToString:[self symbol4End:keyType]]) {
            f_key = FALSE;
        }else if (f_key) {
            s_key = [s_key stringByAppendingString:a_line];
        }
    }
    if (s_key.length == 0) return NULL;
    
    // This will be base64 encoded, decode it.
    NSData *d_key = [[NSData alloc] initWithBase64EncodedString:s_key options:0];
    if(d_key == nil) return NULL;
    
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *keyConfig = [[NSMutableDictionary alloc] init];
    [keyConfig setObject:(id) kSecClassKey forKey:(id)kSecClass];
    [keyConfig setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [keyConfig setObject:d_tag forKey:(id)kSecAttrApplicationTag];
    SecItemDelete((CFDictionaryRef)keyConfig);
    
    CFTypeRef persistKey = nil;
    
    // Add persistent version of the key to system keychain
    [keyConfig setObject:d_key forKey:(id)kSecValueData];
    [keyConfig setObject:[self secAttrKeyClass:keyType] forKey:(id)
     kSecAttrKeyClass];
    [keyConfig setObject:[NSNumber numberWithBool:YES] forKey:(id)
     kSecReturnPersistentRef];
    
    OSStatus secStatus = SecItemAdd((CFDictionaryRef)keyConfig, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem)) {
        //        [privateKey release];
        return NULL;
    }
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    
    [keyConfig removeObjectForKey:(id)kSecValueData];
    [keyConfig removeObjectForKey:(id)kSecReturnPersistentRef];
    [keyConfig setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
    secStatus = SecItemCopyMatching((CFDictionaryRef)keyConfig,
                                    (CFTypeRef *)&keyRef);
    
    if(secStatus != noErr)
        return NULL;
    return keyRef;
}


- (NSString *)tagString4SecKey:(TTRSAKeyType)type{
    return type == TTRSAKeyTypePublic ? kSecPublicKeyTag : kSecPrivateKeyTag;
}

- (NSString *)symbol4Begin:(TTRSAKeyType)type{
    return type == TTRSAKeyTypePublic ? kPublicKeyBegin : kPrivateKeyBegin;
}

- (NSString *)symbol4End:(TTRSAKeyType)type{
    return type == TTRSAKeyTypePublic ? kPublicKeyEnd : kPrivateKeyEnd;
}

- (id)secAttrKeyClass:(TTRSAKeyType)type{
    return type == TTRSAKeyTypePublic ? (id)kSecAttrKeyClassPublic:(id)kSecAttrKeyClassPrivate;
}

#pragma mark - sign and unsign
- (NSData*)secPrivateSignBytesSHA1:(NSData *)plainData privateKey:(SecKeyRef)privateKey{
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA1_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA1([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(privateKey,
                  kSecPaddingPKCS1,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}

- (BOOL)secPublicVerifyBytesSHA1:(NSData *)signatureData plainData:(NSData *)plainData publicKey:(SecKeyRef)publicKey{
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signatureData bytes];
    
    size_t hashBytesSize = CC_SHA1_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA1([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    OSStatus status = SecKeyRawVerify(publicKey,
                                      kSecPaddingPKCS1,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
  
    return (status == 0);
}
#pragma mark - encrypt

- (NSData *)secEncryptByPublicKey:(SecKeyRef)publicKey plainText:(NSString *)plainText{
    
    NSLog(@"== encryptWithPublicKey()");
    
    OSStatus status = noErr;
    uint8_t *plainBuffer;
    uint8_t *cipherBuffer;
    plainBuffer = (uint8_t *)calloc(64, sizeof(uint8_t));
    cipherBuffer = (uint8_t *)calloc(1024, sizeof(uint8_t));
    
    strncpy((char *)plainBuffer, [plainText UTF8String], strlen([plainText UTF8String]));

    [self encryptByPublicKey:publicKey plainBuffer:plainBuffer cipherBuffer:cipherBuffer];
    
    return nil;
}

- (void)encryptByPublicKey:(SecKeyRef)publicKey plainBuffer:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer
{
    
    NSLog(@"== encryptWithPublicKey()");
    
    OSStatus status = noErr;
    
    NSLog(@"** original plain text 0: %s", plainBuffer);
    
    size_t plainBufferSize = strlen((char *)plainBuffer);
    size_t cipherBufferSize = 1024;
    
    NSLog(@"SecKeyGetBlockSize() public = %lu", SecKeyGetBlockSize(publicKey));
    //  Error handling
    // Encrypt using the public.
    status = SecKeyEncrypt(publicKey,
                           kSecPaddingPKCS1,
                           plainBuffer,
                           plainBufferSize,
                           &cipherBuffer[0],
                           &cipherBufferSize
                           );
    NSLog(@"encryption result code: %ld (size: %lu)", status, cipherBufferSize);
    NSLog(@"encrypted text: %s", cipherBuffer);
    
    NSData *decryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    NSString *decryptedString1 = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    NSString *decryptedString = [decryptedData base64EncodedStringWithOptions:0];
    
    uint8_t *pBuffer = (uint8_t *)calloc(1024, sizeof(uint8_t));

    
    [self decryptWithPrivateKey:cipherBuffer plainBuffer:pBuffer];
    
}

- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize = strlen((char *)cipherBuffer);
    
    
    // DECRYPTION
    size_t plainBufferSize = 1024;
    
    //  Error handling
    status = SecKeyDecrypt(privateSecKeyRef,
                           kSecPaddingPKCS1,
                           &cipherBuffer[0],
                           cipherBufferSize,
                           &plainBuffer[0],
                           &plainBufferSize
                           );
    NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}



-(NSString*) rsaEncryptString:(NSString*)string {
    NSData* data = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSData* encryptedData = [self rsaEncryptData: data];
    NSString* base64EncryptedString = [encryptedData base64EncodedStringWithOptions:0];
    return base64EncryptedString;
}
// 加密的大小受限于SecKeyEncrypt函数，SecKeyEncrypt要求明文和密钥的长度一致，如果要加密更长的内容，需要把内容按密钥长度分成多份，然后多次调用SecKeyEncrypt来实现
-(NSData*) rsaEncryptData:(NSData*)data {
    SecKeyRef key = publicSeckeyRef;
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    size_t blockSize = cipherBufferSize - 11;       // 分段加密
    size_t blockCount = (size_t)ceil([data length] / (double)blockSize);
    NSMutableData *encryptedData = [[NSMutableData alloc] init] ;
    for (int i=0; i<blockCount; i++) {
        int bufferSize = (int)MIN(blockSize,[data length] - i * blockSize);
        NSData *buffer = [data subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        OSStatus status = SecKeyEncrypt(key, kSecPaddingPKCS1, (const uint8_t *)[buffer bytes], [buffer length], cipherBuffer, &cipherBufferSize);
        if (status == noErr){
            NSData *encryptedBytes = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
            [encryptedData appendData:encryptedBytes];
        }else{
            if (cipherBuffer) {
                free(cipherBuffer);
            }
            return nil;
        }
    }
    if (cipherBuffer){
        free(cipherBuffer);
    }
    return encryptedData;
}




#pragma mark - Decrypt

-(NSString*) rsaDecryptString:(NSString*)string {
    
    NSData* data = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData* decryptData = [self rsaDecryptData: data];
    NSString* result = [[NSString alloc] initWithData: decryptData encoding:NSUTF8StringEncoding];
    return result;
}

-(NSData*) rsaDecryptData:(NSData*)data {
    SecKeyRef key = privateSecKeyRef;
    size_t cipherLen = [data length];
    void *cipher = malloc(cipherLen);
    [data getBytes:cipher length:cipherLen];
    size_t plainLen = SecKeyGetBlockSize(key) - 12;
    void *plain = malloc(plainLen);
    OSStatus status = SecKeyDecrypt(key, kSecPaddingPKCS1, cipher, cipherLen, plain, &plainLen);
    
    if (status != noErr) {
        return nil;
    }
    
    NSData *decryptedData = [[NSData alloc] initWithBytes:(const void *)plain length:plainLen];
    
    return decryptedData;
}

@end












//
//static int padding = RSA_PKCS1_PADDING;
//
//- (unsigned char *)publicKeyEncrypt:(NSString *)message key:(unsigned char *)key{
//    
//    RSA *rsa = [self createRSA:key public:1];
//    
//    const char *msgInChar = [message UTF8String];
//    unsigned char  encrypted[4028] = {}; //I'm not so sure about this size
//    int bufferSize = RSA_public_encrypt(strlen(msgInChar), (unsigned char *)msgInChar, encrypted, rsa, RSA_PKCS1_PADDING);
//    if (bufferSize == -1) {
//        NSLog(@"Encryption failed");
//    }
//    
//    NSString *encrypteds = [[NSString alloc] initWithCString:(const char*)encrypted encoding:NSASCIIStringEncoding];
//    
//    NSData *data = [NSData dataWithBytes:(const void *)encrypted length:strlen(encrypted)]; //I'm not so sure about this length
//    
//    NSString *r = [data base64EncodedStringWithOptions:0];
//    NSString *result = [self encodeBase64WithData:data];
//    
//    return encrypted;
//}
//
//- (void)pivateKeyDecrypt:(unsigned char *)message key:(unsigned char*)key{
//    
//    RSA *rsa = [self createRSA:key public:0];
//    
//    //    const char *msgInChar = [message UTF8String];
//    unsigned char  encrypted[4028] = {}; //I'm not so sure about this size
//    int bufferSize = RSA_private_decrypt(strlen(message), (unsigned char *)message, encrypted, rsa, RSA_PKCS1_PADDING);
//    if (bufferSize == -1) {
//        char buffer[500];
//        ERR_error_string(ERR_get_error(), buffer);
//        NSLog(@"%@",[NSString stringWithUTF8String:buffer]);
//        NSLog(@"Encryption failed");
//    }
//    
//    NSData *data = [NSData dataWithBytes:(const void *)encrypted length:strlen(encrypted)]; //I'm not so sure about this length
//    
//    NSString *r = [data base64EncodedStringWithOptions:0];
//    NSString *result = [self encodeBase64WithData:data];
//    
//}
//
////int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
////{
////    RSA * rsa = createRSA(key,1);
////    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
////    return result;
////}
////int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
////{
////    RSA * rsa = createRSA(key,0);
////    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
////    return result;
////}
////
////
////int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
////{
////    RSA * rsa = createRSA(key,0);
////    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
////    return result;
////}
////int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
////{
////    RSA * rsa = createRSA(key,1);
////    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
////    return result;
////}
////
//- (void)printLastError:(char *)msg
//{
//    
//    char * err = malloc(130);;
//    ERR_load_crypto_strings();
//    ERR_error_string(ERR_get_error(), err);
//    printf("%s ERROR: %s\n",msg, err);
//    free(err);
//}
//
//
//#pragma mark - rsa data converte
//- (void)converteData2Rsa{
//    [_rsa_keyPaire_data getBytes:&_keyPair length:sizeof(_keyPair)];
//}
//
//- (void)converteRsa2Data{
//    _rsa_keyPaire_data = [NSData dataWithBytes:&_keyPair length:sizeof(_keyPair)];
//}
//
//
//- (RSA *)createRSA:(unsigned char *) key public:(int) public
//{
//    RSA *rsa= RSA_new();
//    BIO *keybio ;
//    keybio = BIO_new_mem_buf(key, -1);
//    if (keybio==NULL)
//    {
//        printf( "Failed to create key BIO");
//        return 0;
//    }
//    if(public)
//    {
//        
//        PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
//        if (rsa == NULL)
//        {
//            char buffer[500];
//            ERR_error_string(ERR_get_error(), buffer);
//            NSLog(@"%@",[NSString stringWithUTF8String:buffer]);
//        }
//        
//        //        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
//        //        if (rsa == NULL)
//        //        {
//        //            char buffer[500];
//        //            ERR_error_string(ERR_get_error(), buffer);
//        //
//        //            [self printLastError:buffer];
//        //        }
//        
//        
//    }
//    else
//    {
//        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
//        if (rsa == NULL)
//        {
//            char buffer[500];
//            ERR_error_string(ERR_get_error(), buffer);
//            NSLog(@"%@",[NSString stringWithUTF8String:buffer]);
//        }
//        
//    }
//    if(rsa == NULL)
//    {
//        printf( "Failed to create RSA");
//    }
//    
//    return rsa;
//}
//
//
//- (NSString *)encodeBase64WithData:(NSData *)objData {
//    const unsigned char * objRawData = [objData bytes];
//    char * objPointer;
//    char * strResult;
//    
//    // Get the Raw Data length and ensure we actually have data
//    size_t intLength = [objData length];
//    if (intLength == 0) return nil;
//    
//    // Setup the String-based Result placeholder and pointer within that placeholder
//    strResult = (char *)calloc(((intLength + 2) / 3) * 4, sizeof(char));
//    objPointer = strResult;
//    
//    // Iterate through everything
//    while (intLength > 2) { // keep going until we have less than 24 bits
//        *objPointer++ = _base64EncodingTable[objRawData[0] >> 2];
//        *objPointer++ = _base64EncodingTable[((objRawData[0] & 0x03) << 4) + (objRawData[1] >> 4)];
//        *objPointer++ = _base64EncodingTable[((objRawData[1] & 0x0f) << 2) + (objRawData[2] >> 6)];
//        *objPointer++ = _base64EncodingTable[objRawData[2] & 0x3f];
//        
//        // we just handled 3 octets (24 bits) of data
//        objRawData += 3;
//        intLength -= 3;
//    }
//    
//    // now deal with the tail end of things
//    if (intLength != 0) {
//        *objPointer++ = _base64EncodingTable[objRawData[0] >> 2];
//        if (intLength > 1) {
//            *objPointer++ = _base64EncodingTable[((objRawData[0] & 0x03) << 4) + (objRawData[1] >> 4)];
//            *objPointer++ = _base64EncodingTable[(objRawData[1] & 0x0f) << 2];
//            *objPointer++ = '=';
//        } else {
//            *objPointer++ = _base64EncodingTable[(objRawData[0] & 0x03) << 4];
//            *objPointer++ = '=';
//            *objPointer++ = '=';
//        }
//    }
//    
//    NSString *strToReturn = [[NSString alloc] initWithBytesNoCopy:strResult length:objPointer - strResult encoding:NSASCIIStringEncoding freeWhenDone:YES];
//    return strToReturn;
//}
//
//- (NSData *)decodeBase64WithString:(NSString *)strBase64 {
//    const char * objPointer = [strBase64 cStringUsingEncoding:NSASCIIStringEncoding];
//    if (objPointer == NULL)  return nil;
//    size_t intLength = strlen(objPointer);
//    int intCurrent;
//    int i = 0, j = 0, k;
//    
//    unsigned char * objResult;
//    objResult = calloc(intLength, sizeof(char));
//    
//    // Run through the whole string, converting as we go
//    while ( ((intCurrent = *objPointer++) != '\0') && (intLength-- > 0) ) {
//        if (intCurrent == '=') {
//            if (*objPointer != '=' && ((i % 4) == 1)) {// || (intLength > 0)) {
//                // the padding character is invalid at this point -- so this entire string is invalid
//                free(objResult);
//                return nil;
//            }
//            continue;
//        }
//        
//        intCurrent = _base64DecodingTable[intCurrent];
//        if (intCurrent == -1) {
//            // we're at a whitespace -- simply skip over
//            continue;
//        } else if (intCurrent == -2) {
//            // we're at an invalid character
//            free(objResult);
//            return nil;
//        }
//        
//        switch (i % 4) {
//            case 0:
//                objResult[j] = intCurrent << 2;
//                break;
//                
//            case 1:
//                objResult[j++] |= intCurrent >> 4;
//                objResult[j] = (intCurrent & 0x0f) << 4;
//                break;
//                
//            case 2:
//                objResult[j++] |= intCurrent >>2;
//                objResult[j] = (intCurrent & 0x03) << 6;
//                break;
//                
//            case 3:
//                objResult[j++] |= intCurrent;
//                break;
//        }
//        i++;
//    }
//    
//    // mop things up if we ended on a boundary
//    k = j;
//    if (intCurrent == '=') {
//        switch (i % 4) {
//            case 1:
//                // Invalid state
//                free(objResult);
//                return nil;
//                
//            case 2:
//                k++;
//                // flow through
//            case 3:
//                objResult[k] = 0;
//        }
//    }
//    
//    // Cleanup and setup the return NSData
//    return [[NSData alloc] initWithBytesNoCopy:objResult length:j freeWhenDone:YES];
//}
//
//
//

//
//static const char _base64EncodingTable[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//static const short _base64DecodingTable[256] = {
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -1, -1, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
//    -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
//    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
//    -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
//    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
//    -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
//    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
//    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
//};
//
