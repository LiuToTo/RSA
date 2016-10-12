//
//  RSA.h
//  OpensslTest
//
//  Created by 刘ToTo on 16/10/12.
//  Copyright © 2016年 com.365ime. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TTRSA : NSObject

- (instancetype)initWithBits:(int)bits;
- (instancetype)initWithRSAKeyPair:(NSData *)rsaKeyPaireData;

@property (nonatomic, copy, readonly) NSString *pem_publicKey;
@property (nonatomic, copy, readonly) NSString *pem_privateKey;

@property (nonatomic, strong, readonly) NSData *rsa_keyPaire_data;

@end
