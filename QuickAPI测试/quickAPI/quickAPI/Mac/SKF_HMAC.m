//
//  SKF_HMAC.m
//  quickAPI
//
//  Created by SecureChip on 2018/1/31.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SKF_HMAC.h"
#import <MultiKey/MultiKey.h>
#import "SimpleSecureCore.h"
#import "IvParameterSpec.h"
#import "Key.h"
#import "AlgorithmParameterSpec.h"
#import "ErrorUtil.h"
#define BLOCK_SIZE 16
@interface SKF_HMAC()
@property(nonatomic,strong)SecureCoreDevice *device;
@property(nonatomic,strong)id<IContainer,ISignKey> con;
@property(nonatomic,strong)id<ISessionKey> sessionkey;
@property(nonatomic,strong)BlockCipherParam *macBlockCipherParam;
@property(nonatomic,strong)id<IMac> mac;
@property(nonatomic,strong)SimpleSecureCore *simpleSecureCore;
@end
@implementation SKF_HMAC

-(instancetype)init{
    self = [super init];
    if (self) {
        self.simpleSecureCore = [SimpleSecureCore getinstance];
        self.device = [self.simpleSecureCore getDefaultDevice];
    }
    return self;
}
- (void)engineInit:(id<Key>)key algorithmparameterSpec:(id<AlgorithmParameterSpec>)algorithmparameterSpec err:(NSError *__autoreleasing *)err {
    NSInteger ret = SAR_OK;
    NSData *keyEncoded = [key getEncoded];
    if (key == nil){
        NSLog(@"engineInit: key is null");
        ret = SAR_OBJERR;
    }else if(keyEncoded.length != BLOCK_SIZE){
        NSLog(@"engineInit: key length should be %d",BLOCK_SIZE);
        ret = SAR_INVALIDPARAMERR;
    }else if(![algorithmparameterSpec isMemberOfClass:[IvParameterSpec class]]){
        NSLog(@"engineInit: algorithmparameterSpec is not IvParameterSpec");
        ret = SAR_INVALIDPARAMERR;
    }else if([(IvParameterSpec*)algorithmparameterSpec getIv].length!=BLOCK_SIZE){
        NSLog(@"engineInit: IV length should be %d",BLOCK_SIZE);
        ret = SAR_INDATALENERR;
    }
    if(ret != SAR_OK){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:ret errorMessage:@"engineInit: ret is not ok"];
        return;
    }
    NSError *error = nil;
    self.device = [self.simpleSecureCore getDefaultDevice];
    self.con = [self.simpleSecureCore getDefaultContainer];
    NSData *publicKey = [self.con SKF_ExportPublicKey:false err:&error];
    if (publicKey == nil){
        if(err!=nil){
            *err = error;
            NSLog(@"engineInit: SKF_ExportPublicKey err is %@",error.localizedDescription);
        }
        return;
    }
    ECCPublicKeyBlob *publicKeyBlob = [ECCPublicKeyBlob new];
    [publicKeyBlob readFromByteArray:publicKey];
    ECCCipherBlob *wrappedKeyCipherBlob = [ECCCipherBlob new];
    ret = [self.device SKF_ExtECCEncrypt:publicKeyBlob plainText:keyEncoded cipherBlob:&wrappedKeyCipherBlob];
    if (ret != SAR_OK){
        NSLog(@"engineInit: SKF_ExtECCEncrypt err is %@",[resultCode toString:ret]);
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:ret errorMessage:@"engineInit: SKF_ExtECCEncrypt err"];
        return;
    }
    NSData *wrappedKey = [wrappedKeyCipherBlob toByteArray];
    self.sessionkey = [self.con SKF_ImportSessionKey:[self.simpleSecureCore getDefaultPIN] alg:SGD_SM4_CBC wrapedData:wrappedKey err:&error];
    if (error != nil||self.sessionkey == nil){
        NSLog(@"engineInit: SKF_ImportSessionKey err is %@",error.localizedDescription);
        if(err!=nil)
            *err = error;
        return;
    }
    self.macBlockCipherParam = [BlockCipherParam new];
    [self.macBlockCipherParam setPaddingType:0];
    [self.macBlockCipherParam setiv:[(IvParameterSpec *)algorithmparameterSpec getIv]];
    [self engineReset:err];
}

- (void)engineReset:(NSError *__autoreleasing *)err {
    self.mac = [self.sessionkey SKF_MacInit:self.macBlockCipherParam err:err];
    if (err != nil&& *err!=nil)
        NSLog(@"engineReset: SKF_MacInit err is %@",(*err).localizedDescription);
}

- (NSInteger)engineUpdate:(Byte)input {
    Byte inputArray[1] = {input};
    NSData *data = [NSData dataWithBytes:inputArray length:1];
    return [self engineUpdate:data offset:0 len:1];
}

- (NSInteger)engineUpdate:(NSData *)input offset:(NSInteger)offset len:(NSInteger)len {
    NSRange range = NSMakeRange(offset, len);
    NSData *data = [input subdataWithRange:range];
    ResultCode ret = [self.mac SKF_MacUpdate:data];
    if (ret != SAR_OK)
        NSLog(@"engineUpdate: SKF_MacUpdate err is %@",[resultCode toString:ret]);
    return ret;
}

-(NSInteger)engineGetMacLength{
    return BLOCK_SIZE;
}
- (NSData *)engineDoFinal:(NSError *__autoreleasing *)err {
    NSData *macData = [self.mac SKF_MacFinal:err];
    if (err != nil && *err!=nil)
        NSLog(@"engineFinal: SKF_MacFinal err is %@",(*err).localizedDescription);
    return macData;
}
@end
