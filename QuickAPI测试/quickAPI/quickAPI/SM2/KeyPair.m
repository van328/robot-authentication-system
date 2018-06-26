//
//  KeyPair.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/26.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "KeyPair.h"
#import "PublicKey.h"
#import "PrivateKey.h"
@interface KeyPair()
@property(nonatomic,strong)id<PrivateKey> mPrivateKey;
@property(nonatomic,strong)id<PublicKey> mPublicKey;
@end
@implementation KeyPair
-(instancetype)init:(id<PublicKey>)publicKey privateKey:(id<PrivateKey>)privateKey{
    if (self = [super init]){
        self.mPublicKey = publicKey;
        self.mPrivateKey = privateKey;
    }
    return self;
}
-(id<PublicKey>)getPublic{
    return self.mPublicKey;
}
-(id<PrivateKey>)getPrivate{
    return self.mPrivateKey;
}
@end
