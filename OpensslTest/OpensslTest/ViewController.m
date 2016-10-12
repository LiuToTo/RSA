//
//  ViewController.m
//  OpensslTest
//
//  Created by 刘ToTo on 16/10/11.
//  Copyright © 2016年 com.365ime. All rights reserved.
//

#import "ViewController.h"
#import "TTRSA.h"

@interface ViewController ()

@end

@implementation ViewController



- (void)viewDidLoad {
    [super viewDidLoad];
    
    [[TTRSA alloc] initWithBits:1024];
    // Do any additional setup after loading the view, typically from a nib.
//
//    NSData *publicData = [NSData dataWithBytes:&keypair length:sizeof(keypair)];
//    RSA *mypublickey = NULL;
//    [publicData getBytes:&mypublickey length:sizeof(mypublickey)];
//    
//    
//    unsigned char *data = "123";
//    
//    
//    RSA *public = createRSA(pub_key,1);
    
}




@end
