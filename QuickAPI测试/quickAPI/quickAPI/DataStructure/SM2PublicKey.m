//
//  SM2PublicKey.m
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SM2PublicKey.h"

@interface SM2PublicKey()
@property (strong,nonatomic) ECCPublicKeyBlob *publicKey;
@end
@implementation SM2PublicKey
-(instancetype)initWithPublicKey:(NSData *)publicKey{
    if(self = [super init]){
        self.publicKey = [[ECCPublicKeyBlob alloc]init];
        [self.publicKey readFromByteArray:publicKey];
    }
    return self;
}
- (ECCPublicKeyBlob *)getPublicKeyBlob{
    return self.publicKey;
}

- (NSData *)toByteArray{
    return [self.publicKey toByteArray];
}

- (NSString *)getAlgorithm {
    return @"SM2";
}

- (NSData *)getEncoded {
    return nil;
}

- (NSString *)getFormat {
    return nil;
}

@end
