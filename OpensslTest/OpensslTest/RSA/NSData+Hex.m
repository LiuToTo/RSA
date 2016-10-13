//
//  NSData+Hex.m
//  OpensslTest
//
//  Created by 刘ToTo on 16/10/13.
//  Copyright © 2016年 com.365ime. All rights reserved.
//

#import "NSData+Hex.h"

@implementation NSData (Hex)

- (NSString*)toHexStringByLength: (unsigned int) length {
    uint8_t *digest = (uint8_t *)[self bytes];
    NSMutableString* hash = [NSMutableString stringWithCapacity:length * 2];
    for (unsigned int i = 0; i < length; i++) {
        [hash appendFormat:@"%02x", digest[i]];
        digest[i] = 0;
    }
    return hash;
}

@end
