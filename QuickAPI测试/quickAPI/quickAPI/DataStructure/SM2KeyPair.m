//
//  SM2KeyPair.m
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SM2KeyPair.h"
@interface SM2KeyPair()
@property (nonatomic,strong) NSData * publicKey;
@property (nonatomic,strong) NSData * privateKey;
@property (nonatomic,copy) NSString * privateAlias;
@end
@implementation SM2KeyPair
-(instancetype)initWithPublicKey:(NSData *)publicKey PrivateKey:(NSData *)privateKey PrivateAlias:(NSString *)privateAlias{
    if (self = [super init]){
        self.publicKey = publicKey;
        self.privateKey = privateKey;
        self.privateAlias = privateAlias;
    }
    return self;
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
- (NSData *)getPublicKey {
    return self.publicKey;
}

-(void)setPublicKey:(NSData *) publicKey {
    _publicKey = publicKey;
}

- (NSData *) getPrivateKey {
    return self.privateKey;
}

- (void) setPrivateKey:(NSData *) privateKey {
    self.privateKey = privateKey;
}

- (NSString *) getPrivateAlias {
    return self.privateAlias;
}

- (void) setPrivateAlias:(NSString *) privateAlias {
    self.privateAlias = privateAlias;
}

@end
