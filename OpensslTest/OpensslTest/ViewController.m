//
//  ViewController.m
//  OpensslTest
//
//  Created by 刘ToTo on 16/10/11.
//  Copyright © 2016年 com.365ime. All rights reserved.
//

#import "ViewController.h"
#import "NSString+Hex.h"
#import "TTRSA.h"

NSString *pubk = @"-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApnHiE8ao2ZtleP0KJLFS\nPkOVhMUlFNCFKFEEt17KZFjUM3ZhhPlahxq038dejBICFDsEHvXZ8T+8UKBDQI6/\nDAUgparqUqE4gqSiQeGFDhrY8cBi7lAD/h7u4FI1+nEbHf7JkfhDz57HZhgf/l6r\nKNEr7sqkdCJKp2XFqJVzfDs3vnQI0NCiVQeJysjTXRzH8VMNv9exV9ZrSasjA57V\nNaUN9fZnvewqUEvTTzFwXVeV0FDXbYUq0cFGMjFB+gCFpaOMSQpQayZEWsdpMTMY\nTt84VHVZ+aVtBYxdmXk/hilodQsNiK3dmM54lwvo+8N2M1jQyOlP+QWPWilzPI+h\n4wIDAQAB\n-----END RSA PUBLIC KEY-----";
NSString *prik = @"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEApnHiE8ao2ZtleP0KJLFSPkOVhMUlFNCFKFEEt17KZFjUM3Zh\nhPlahxq038dejBICFDsEHvXZ8T+8UKBDQI6/DAUgparqUqE4gqSiQeGFDhrY8cBi\n7lAD/h7u4FI1+nEbHf7JkfhDz57HZhgf/l6rKNEr7sqkdCJKp2XFqJVzfDs3vnQI\n0NCiVQeJysjTXRzH8VMNv9exV9ZrSasjA57VNaUN9fZnvewqUEvTTzFwXVeV0FDX\nbYUq0cFGMjFB+gCFpaOMSQpQayZEWsdpMTMYTt84VHVZ+aVtBYxdmXk/hilodQsN\niK3dmM54lwvo+8N2M1jQyOlP+QWPWilzPI+h4wIDAQABAoIBAGxQ5lgKSy25o/J1\ncVlpj+T3JGFPzo7aGB2hg9k1Na7R495Npq7bet87MQQEAXJT8chqk4b2ZUtLN+ic\nMsfbXVacK5/EN1NomZbjPrhy45zHOfExSvBdYAvK45dVyMzfOE9v1ItKrg55/Ldi\n8cceonIglV+DvjvZaQ3A/D12bL4l2qlZICTpgjK3yGshEWrdEwIk36LRiefPLCqW\nYE/4TTOHkd80PDX2QmBUtYmBsq0nrUQqr1wFbaiDC3G3wctarNSUJds6Z4KILFOq\nOUZfnmL1cEQfyr7Q9i2ZLDqR+b4PAluE0BEenn0HsaVD4ug17gD/YDHUSz0LhmCq\npu6vB7kCgYEA0uhWrSYc+qjgR+dlWSlaurnEIQMh7oV6y/RXvmwc9aOBHQDjvP7+\ntFcxizC4uMNR6HkPwkWN7wuCnbbKWZqvjuY/jj2jtAqRrBgpRNV3q3UD0Y2fGV2Q\ndiSdXeQfJKV490AKMHlyZ+mHsOJjcODW9F6IuAavVw8X+/pDSnS4oPUCgYEAygf0\nYEtj8Pk1FhawXCLaINyiI9kKam1RTeSdI9vj06zJa92VpQxbWKdDptGmfCwDM5lw\nG+SF6hxmdHKqyvEEjRWXqL2vYWvWRlntl15NRN744mN1nPdelDHF4Hqg4OAe1+sc\nnAdrPelkNlTtYGy+pZm9edFR3J89kwNoFeOHkHcCgYBSKmn6Mur/TGN0H9YAEnhi\nXpTmN440mpPoeVzltsDhgb1/SyVuL/mS0JVgoK6WbKGwa9mT2f0dr+JHBzt2BSl4\nBoOkKqdoMOXnodISGwfwKDpAnWfqPeVV4ZXdSk5HvJ+P08ckc2v6x6QxaUFMbIvR\n0DJ7Xz9YL20soactjqOPMQKBgQCv48cFgv1q0Xw/U9eND6a6j3v2G8Kur6fmWc/Z\nZVpvcnIWH99lx2FLyKvkc4gveR38cWyiTA2uqbUlUqORdc5Rimf0N9iVx43QyABL\nFYXOHRWv+4ls9Ax6lu7ApeKkhVs0/nN1AByE1Uoy5zOXDHXatQO6J9vOaTDxajjX\nPbVLtwKBgDBMlTjPXOJbdiCVe8y+F4MTuykrveGf9MF7MqQU3Mtsaf0w5Jq33gAf\nKhlSpREs3YRXjxEahAoqmPQQGPEpmCpKJaFVKJrgGikmso34sS87IgLCGwwO/H5C\nKPTWKBwkLR7FzYgZdgHQQTpl+2wEe12/IYbMhewRY7mdlrOwXdQT\n-----END RSA PRIVATE KEY-----";

@interface ViewController ()

@end

@implementation ViewController



- (void)viewDidLoad {
    [super viewDidLoad];
    
    TTRSA *rsaTest = [[TTRSA alloc] initWithBits:2048 privateTag:@"com.365ime.private" publicTag:@"com.365ime.public"];
    
    // sha1
    NSData *sha1 = [@"111" sha1];
    
    // sign
    NSData *cipherData = [rsaTest signPKCS1PlainData:sha1];
    
    // base64
    NSString *cipherText = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSLog(@"cipherText :%@",cipherText);
    
    // verify
    BOOL isVerified =[rsaTest verifyPKCS1SignedData:[[NSData alloc] initWithBase64EncodedString:cipherText options:NSDataBase64DecodingIgnoreUnknownCharacters] plainData:sha1];
    NSLog(@"sign and verify result : %d",isVerified);
    
    NSString *originText = @"liuxu123_dfgdjjsdgf_tt";
    NSString *encryptText = [rsaTest encryptPKCS1PlainText:originText];
    NSString *decryptText = [rsaTest decryptPKCS1CipherText:encryptText];
    
    if ([originText isEqualToString:decryptText]) {
        NSLog(@"encrypt and decrypt:successful");
    }else{
        NSLog(@"encrypt and decrypt:failed");
    }
    
    
    #pragma mark - convenient
    NSData *signD = [TTRSA signPKCS1PrivateTag:@"pri_tag" privateKey:prik plainData:sha1];
    BOOL ok = [TTRSA verifyPKCS1PublicTag:@"pub_tag" publicKey:pubk plainData:sha1 signedData:signD];
    NSLog(@"%d",ok);
    
}




@end
