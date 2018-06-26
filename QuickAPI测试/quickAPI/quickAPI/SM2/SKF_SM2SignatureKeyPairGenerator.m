//
//  SKF_SM2SignatureKeyPairGenerator.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/11.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SKF_SM2SignatureKeyPairGenerator.h"
#import "SM2KeyPair.h"
#import "SM2PublicKey.h"
#import "SM2PrivateKey.h"
#import "SM2KeyPairParameter.h"
#import "ErrorUtil.h"
#import <MultiKey/MultiKey.h>
#import "SimpleSecureCore.h"
#import "KeyPair.h"
@class KeyPair;
@interface SKF_SM2SignatureKeyPairGenerator()
@property(nonatomic,strong)KeyPair *keyPair;
@property(nonatomic,strong)NSString *keyAlias;
@property(nonatomic,strong)SCContainer *con;
@property(nonatomic,strong)SCApplication *app;
@property(nonatomic,strong)SimpleSecureCore *core;
@end
@implementation SKF_SM2SignatureKeyPairGenerator
-(instancetype)init{
    if (self = [super init]){
        self.core = [SimpleSecureCore getinstance];
        self.app = [self.core getDefaultApplication];
    }
    return self;
}
- (KeyPair *)generateKeyPair {
    return self.keyPair;
}

- (void)initialize:(NSInteger)keysize random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
    
}

- (void)initializeWithParam:(id<AlgorithmParameterSpec>)params random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
    if ([params isMemberOfClass:[SM2KeyPairParameter class]]){
        SM2KeyPairParameter *param = (SM2KeyPairParameter*)params;
        self.keyAlias = [param getKeyPairAlias];
    }else{
        NSLog(@"initializeWithParam: not support this parameter");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"initializeWithParam: not support this parameter"];
        return;
    }
    self.con = (SCContainer*)[self.app SKF_CreateContainer:self.keyAlias err:err];
    if([resultCode toString:SAR_OK] != (*err).localizedDescription){
        if ([resultCode toString:SAR_CONTAINERALREADYEXIST] == (*err).localizedDescription){
            self.con = (SCContainer*)[self.app SKF_OpenContainer:self.keyAlias err:err];
            if ([resultCode toString:SAR_CONTAINERALREADYOPENED] == (*err).localizedDescription){
                NSLog(@"initializeWithParam: container already exist");
                return;
            }
        }else{
            NSLog(@"initializeWithParam: create container failed");
            return;
        }
    }
    ECCPublicKeyBlob *publicKeyBlob = [ECCPublicKeyBlob new];
    NSString *mappID = [self.core getAppID];
    NSString *mappSecret = [self.core getAppSecret];
    ServerInfo *addr = [self.core getAddr];
    NSMutableArray *array = [NSMutableArray new];
    [array addObject:addr];
    BOOL e = true;
    ResultCode rs = [self.con SKF_CheckKeyPairExistence:e];
    if (rs != SAR_OK ) {
        ResultCode rs = [self.con SKF_GenECCKeyPair:[self.core getDefaultPIN] alg:SGD_SM2_1 appID:mappID appSecret:mappSecret list:array pubKeyBlob:&publicKeyBlob];
        if(rs != SAR_OK){
             NSLog(@"SKF_SM2SignatureKeyPairGenerator initialize: SKF_GenECCKeyPair fail");
        }
    }else{
        NSData* pubKey = [self.con SKF_ExportPublicKey:true err:err];
        [publicKeyBlob readFromByteArray:pubKey];
    }
   self.keyPair = [[KeyPair alloc]init:[[SM2PublicKey alloc] initWithPublicKey:[publicKeyBlob toByteArray]] privateKey:[[SM2PrivateKey alloc] initWithAlias:self.keyAlias]];
    [self.con SKF_CloseContainer];
}

@end
