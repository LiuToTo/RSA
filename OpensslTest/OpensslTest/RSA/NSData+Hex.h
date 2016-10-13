//
//  NSData+Hex.h
//  OpensslTest
//
//  Created by 刘ToTo on 16/10/13.
//  Copyright © 2016年 com.365ime. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (Hex)

- (NSString*)toHexStringByLength: (unsigned int) length;

@end
