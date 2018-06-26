//
//  SKF_SM2CipherKeyPairGenerator.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/11.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SKF_SM2CipherKeyPairGenerator.h"
#import "SM2KeyPairParameter.h"
#import "SimpleSecureCore.h"
#import <MultiKey/MultiKey.h>
#import "ErrorUtil.h"
#import "KeyPair.h"
#import "SM2PublicKey.h"
#import "SM2PrivateKey.h"
@interface SKF_SM2CipherKeyPairGenerator()
@property(nonatomic,strong)KeyPair *mKeyPair;
@property(nonatomic,strong)SimpleSecureCore *core;
@property(nonatomic,strong)SecureCoreDevice *device;
@end
@implementation SKF_SM2CipherKeyPairGenerator

- (KeyPair *)generateKeyPair { 
    return self.mKeyPair;
}

- (void)initialize:(NSInteger)keysize random:(SecureRandom *)random err:(NSError *__autoreleasing *)err { 
    
}

- (void)initializeWithParam:(id<AlgorithmParameterSpec>)params random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
    if ([params isMemberOfClass:[SM2KeyPairParameter class]]){
        NSString *alias = [(SM2KeyPairParameter*)params getKeyPairAlias];
        self.core = [SimpleSecureCore getinstance];
        self.device = [self.core getDefaultDevice];
        ECCKeyPairBlob *eccKeyPairBlob = [self.device generateECCKeyPair:err];
        if (*err != nil){
            NSLog(@"initializeWithParam: generateECCKeyPair err is %@",(*err).localizedDescription);
            return;
        }
        NSData *privateKey = eccKeyPairBlob.priKey;
        ECCPublicKeyBlob *publicKeyBlob = eccKeyPairBlob.mECCPublicKeyBlob;
        NSData *publicKey = [publicKeyBlob toByteArray];
        ResultCode rs = [self.core importEccKeyPair:alias publicKey:publicKey privateKey:privateKey ];
        if (rs == SAR_OK){
            self.mKeyPair = [[KeyPair alloc]init:[[SM2PublicKey alloc] initWithPublicKey:publicKey] privateKey:[[SM2PrivateKey alloc] initWithAlias:alias]];
            return;
        }
        if (rs == SAR_CONTAINERALREADYEXIST){
            NSLog(@"initializeWithParam: alias already exists");
            if (err != nil)
                *err = [ErrorUtil geterrorWithCode:SAR_CONTAINERALREADYEXIST errorMessage:@"initializeWithParam: alias already exists"];
            return;
        }else if (rs == SAR_FAIL){
            NSLog(@"initializeWithParam: initialize keypair fail");
            if (err != nil)
                *err = [ErrorUtil geterrorWithCode:SAR_FAIL errorMessage:@"initializeWithParam: initialize keypair fail"];
            return;
        }else{
            NSLog(@"initializeWithParam: invalid param err is %@",[resultCode toString:rs]);
            if (err != nil)
                *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"initializeWithParam: invalid param err"];
            return;
        }
    }else{
        NSLog(@"initializeWithParam: not support this param ");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"initializeWithParam: not support this param"];
        return;
    }
}


@end
