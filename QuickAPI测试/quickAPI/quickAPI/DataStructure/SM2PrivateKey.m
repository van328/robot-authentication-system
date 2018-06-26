//
//  SM2PrivateKey.m
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SM2PrivateKey.h"
@interface SM2PrivateKey()
@property (nonatomic,copy) NSString *privateKeyAlias;
@end
@implementation SM2PrivateKey
- (instancetype)initWithAlias:(NSString *)privateKeyAlias{
    if (self = [super init]){
        self.privateKeyAlias = privateKeyAlias;
    }
    return self;
}
- (NSString *)getPrivateKeyAlias{
    return self.privateKeyAlias;
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

- (void)destroy {
    return;
}

- (BOOL)isDestroyed {
    return NO;
}

@end
