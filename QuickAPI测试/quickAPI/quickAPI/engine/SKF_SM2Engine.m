//
//  SKF_SM2Engine.m
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SKF_SM2Engine.h"
#import "SimpleSecureCore.h"
#import "SM2PublicKey.h"
#import "ErrorUtil.h"
#import "Key.h"
#import <MultiKey/MultiKey.h>
@interface SKF_SM2Engine()
@property (nonatomic,assign) BOOL isInitilized;
@property (nonatomic,assign) BOOL isForEncryption;
@property (nonatomic,strong) id<Key> key;
@property (nonatomic,strong) SecureCoreDevice *device;
@property (nonatomic,strong) SimpleSecureCore *core;
@property (nonatomic,strong) SCContainer *con;
@end
@implementation SKF_SM2Engine
-(BOOL)signatureInitializeWithSimplecore:(SimpleSecureCore *)core container:(id<ISignKey,IContainer>)container{
    if(core == nil || container == nil){
        NSLog(@"the core or container is nil");
        self.isInitilized = NO;
        self.isForEncryption = NO;
        return NO;
    }
    self.core = core;
    self.con = container;
    self.isInitilized = YES;
    self.isForEncryption = NO;
    self.key = nil;
    return YES;
}
-(BOOL)verifyInitializeWithKey:(id<Key>)key device:(SecureCoreDevice *)device{
    if(key == nil || device == nil || [key isMemberOfClass:[SM2PublicKey class]]==NO){
        NSLog(@"the key or device is nil,or the key is not the instance of SM2PublicKey");
        self.isInitilized = NO;
        self.isForEncryption = NO;
        return NO;
    }
    self.isForEncryption = NO;
    self.isInitilized = YES;
    self.device = device;
    self.key = key;
    return YES;
}
-(BOOL)decryptInitializeWithSimplecore:(SimpleSecureCore *)core container:(id<ISignKey,IContainer>)container{
    if(core == nil || container == nil){
        NSLog(@"the core or container is nil");
        self.isInitilized = NO;
        self.isForEncryption = NO;
        return NO;
    }
    self.core = core;
    self.con = container;
    self.isInitilized = YES;
    self.isForEncryption = NO;
    self.key = nil;
    return YES;
}
-(BOOL)encryptInitializeWithKey:(id<Key>)key device:(SecureCoreDevice *)device{
    if(key == nil || device == nil || ([key isMemberOfClass:[SM2PublicKey class]]==NO)){
        NSLog(@"the key or device is nil,or the key is not the instance of SM2PublicKey");
        self.isInitilized = NO;
        self.isForEncryption = NO;
        return NO;
    }
    self.isForEncryption = YES;
    self.isInitilized = YES;
    self.device = device;
    self.key = key;
    return YES;
}
-(NSData *)processCrypto:(NSData *)input offset:(NSInteger)offset length:(NSInteger)length error:(NSError *__autoreleasing *)err{
    if(self.isForEncryption)
        return [self encryptWithPlain:input offset:offset length:length error:err];
    else
        return [self decryptWithCipher:input offset:offset length:length error:err];
    
}
-(NSData*)encryptWithPlain:(NSData *)input offset:(NSInteger)offset length:(NSInteger)length error:(NSError *__autoreleasing *)err{
    if(!self.isInitilized){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"decryptWithCipher: not initialize err"];
        return nil;
    }
    if(input == nil || offset+length>input.length){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"decryptWithCipher: invalid param err"];
        return nil;
    }
    NSData *data = [input subdataWithRange:NSMakeRange(offset, length)];
    NSData *publicBytes = [(SM2PublicKey *)self.key toByteArray];
    ECCPublicKeyBlob *publicKeyBlob = [[ECCPublicKeyBlob alloc]init];
    [publicKeyBlob readFromByteArray:publicBytes];
    ECCCipherBlob *cipher = nil;
    ResultCode ret = [self.device SKF_ExtECCEncrypt:publicKeyBlob plainText:data cipherBlob:&cipher];
    NSData *result = (cipher == nil)?nil:[cipher toByteArray];
    if(err!=nil)
        *err = (ret == SAR_OK)?nil:[ErrorUtil geterrorWithCode:ret errorMessage:@"decryptWithCipher: SKF_ExtECCEncrypt is not ok"];
    return result;
}
-(NSData *)decryptWithCipher:(NSData *)input offset:(NSInteger)offset length:(NSInteger)length error:(NSError *__autoreleasing *)err{
    if(!self.isInitilized){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"encryptWithPlain: not initialized err"];
        return nil;
    }
    if(input == nil || offset+length>input.length){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"encryptWithPlain: invalid param err"];
        return nil;
    }
    NSData *data = [input subdataWithRange:NSMakeRange(offset, length)];
    
    ECCCipherBlob *cipherBlob = [[ECCCipherBlob alloc]init];
    [cipherBlob readFromByteArray:data];
    NSData *plain = [self.con SKF_ECCDecrypt:[self.core getDefaultPIN] cipherBlob:cipherBlob err:err];
    return plain;
}
-(NSData *)processSignature:(NSData *)data error:(NSError *__autoreleasing *)err{
    if(!self.isInitilized){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"processSignature: not initialize err"];
        return nil;
    }
    if(data == nil ){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"processSignature: invalid param err"];
        return nil;
    }
    ECCSignatureBlob *signature = nil;
    ResultCode ret = [self.con SKF_ECCHashAndSignData:[self.core getDefaultPIN] data:data signatureBlob:&signature];
    if(err!=nil)
        *err = (ret == SAR_OK)?nil:[ErrorUtil geterrorWithCode:ret errorMessage:@"processSignature: SKF_ECCHashAndSignData is not ok"];
    NSData *result = nil;
    if(ret == SAR_OK){
        NSMutableData *signBytes = [[NSMutableData alloc]initWithData:signature.r];
        [signBytes appendData:signature.s];
        result = [signBytes copy];
    }
    return result;
}
@end
