//
//  SKF_SM2Signer.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/22.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SKF_SM2Signer.h"
#import <MultiKey/MultiKey.h>
#import "PrivateKey.h"
#import "PublicKey.h"
#import "SM2PublicKey.h"
#import "SM2PrivateKey.h"
#import "SimpleSecureCore.h"
#import "ErrorUtil.h"
#import "SKF_SM2Engine.h"
@interface SKF_SM2Signer()
@property(nonatomic,strong)SimpleSecureCore *core;
@property(nonatomic,strong)ECCPublicKeyBlob *publickeyblob;
@property(nonatomic,strong)SCApplication *app;
@property(nonatomic,strong)SCContainer *con;
@property(nonatomic,strong)SKF_SM2Engine *engine;
@property(nonatomic,strong)SecureCoreDevice *device;
@property(nonatomic,strong)NSMutableData *bOut;
@end
@implementation SKF_SM2Signer

-(instancetype)init{
    self = [super init];
    if (self) {
        self.bOut  = [NSMutableData new];
    }
    return self;
}

- (id)engineGetParameter:(NSString *)param err:(NSError *__autoreleasing *)err {
    return nil;
}

- (id)engineGetParameters {
    return nil;
}

- (void)engineInitSign:(id<PrivateKey>)privateKey err:(NSError *__autoreleasing *)err {
    self.bOut = [NSMutableData new];
    if ([privateKey isKindOfClass:[SM2PrivateKey class]]){
        self.core = [SimpleSecureCore getinstance];
        NSString *name = [(SM2PrivateKey*)privateKey getPrivateKeyAlias];
        self.app = [self.core getDefaultApplication];
        self.con = (SCContainer*)[self.app SKF_OpenContainer:name err:err];
        if (*err != nil){
            if ([resultCode toString:SAR_CONTAINERNOTEXIST] == (*err).localizedDescription){
                NSLog(@"engineInitSign-SKF_OpenContainer: key not exits, please generate first");
                return;
            }else if ([resultCode toString:SAR_CONTAINERALREADYOPENED] == (*err).localizedDescription){
                NSLog(@"engineInitSign-SKF_OpenContainer: key is being used, please dofinal first");
                return;
            }else{
                NSLog(@"engineInitSign: SKF_OpenContainer fail");
                return;
            }
        }
        self.engine = [SKF_SM2Engine new];
        [self.engine signatureInitializeWithSimplecore:self.core container:self.con];
    }else{
        NSLog(@"engineInitSign: not supoort this key type");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"engineInitSign: not supoort this key type"];
        return;
    }
}

- (void)engineInitSign:()privateKey random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
}

- (void)engineInitVerify:(id<PublicKey>)publicKey err:(NSError *__autoreleasing *)err {
    self.bOut = [NSMutableData new];
    if ([publicKey isKindOfClass:[SM2PublicKey class]]){
        self.core = [SimpleSecureCore getinstance];
        self.publickeyblob = [(SM2PublicKey*)publicKey getPublicKeyBlob];
        if (self.publickeyblob == nil){
            if (err != nil)
                *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"engineInitVerify: SAR_NOTSUPPORTYETERR"];
        }
    }
}

- (void)engineSetParameter:(id)params err:(NSError *__autoreleasing *)err {
}

- (void)engineSetParameter:(NSString *)param value:(id)value {
}

- (NSData *)engineSign:(NSError *__autoreleasing *)err {
    if (self.con == nil){
        NSLog(@"engineSign: not initialized");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"engineSign: not initialized"];
        return nil;
    }
    ECCSignatureBlob *eccsignatureBlob = [ECCSignatureBlob new];
    ResultCode rs = [self.con SKF_ECCHashAndSignData:[self.core getDefaultPIN] data:self.bOut signatureBlob:&eccsignatureBlob];
    if (rs != SAR_OK){
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:rs errorMessage:@"engineSign: SKF_ECCHashAndSignData is not ok"];
        return nil;
    }
    self.bOut = [NSMutableData new];
    [self.con SKF_CloseContainer];
    NSMutableData *rsdata = [NSMutableData dataWithData:eccsignatureBlob.r];
    [rsdata appendData:eccsignatureBlob.s];
    return rsdata;
}

- (NSInteger)engineSign:(NSData *)outbuf offset:(NSInteger)offset len:(NSInteger)len err:(NSError *__autoreleasing *)err {
    return 0;
}

- (void)engineUpdate:(NSData *)input {
    [self.bOut appendData:input];
}

- (void)engineUpdate:(Byte)b err:(NSError *__autoreleasing *)err {
    Byte byte[] = {b};
    [self.bOut appendBytes:byte length:1];
}

- (void)engineUpdate:(NSData *)b off:(NSInteger)off len:(NSInteger)len err:(NSError *__autoreleasing *)err {
    NSData *data = [b subdataWithRange:NSMakeRange(off, len)];
    [self.bOut appendData:data];
}

- (BOOL)engineVerify:(NSData *)sigBytes err:(NSError *__autoreleasing *)err {
    self.device = [self.core getDefaultDevice];
    ECCSignatureBlob* eccsignatureBlob = [[ECCSignatureBlob alloc]init];
    eccsignatureBlob.r = [sigBytes subdataWithRange:NSMakeRange(0, 32)];
    eccsignatureBlob.s = [sigBytes subdataWithRange:NSMakeRange(32, 32)];
    ResultCode rs = [self.device SKF_ECCHashAndVerify:self.publickeyblob data:self.bOut signatureBlob:eccsignatureBlob];
    if (rs == SAR_OK)
        return YES;
    else
        return NO;
}

- (BOOL)engineVerify:(NSData *)sigBytes offset:(NSInteger)offset len:(NSInteger)len err:(NSError *__autoreleasing *)err {
    return NO;
}

- (AlgorithmParameters *)engineGetParameters:(NSError *__autoreleasing *)err {
    return nil;
}


@end
