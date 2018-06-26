//
//  SKF_SM2Cipher.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/9.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SKF_SM2Cipher.h"
#import "ErrorUtil.h"
#import <MultiKey/MultiKey.h>
#import "SKF_SM2Engine.h"
#import "SimpleSecureCore.h"
#import "CipherMode.h"
#import "SM2PublicKey.h"
#import "SM2PrivateKey.h"
#import "SM2KeyPair.h"
@interface SKF_SM2Cipher()
@property(nonatomic,strong)SKF_SM2Engine *sm2Engine;
@property(nonatomic,strong)SimpleSecureCore *secureCore;
@property(nonatomic,strong)SecureCoreDevice *device;
@property(nonatomic,strong)SCContainer *con;
@property(nonatomic,strong)SCApplication *app;
@end
@implementation SKF_SM2Cipher
- (instancetype)init
{
    self = [super init];
    if (self) {
        self.sm2Engine = [SKF_SM2Engine new];
    }
    return self;
}
-(NSData*)getOutput:(NSData *)input offset:(NSInteger)offset length:(NSInteger)length error:(NSError *__autoreleasing *)err{
    NSData *result = [self.sm2Engine processCrypto:input offset:offset length:length error:err];
    if (err != nil)
        NSLog(@"getOutput: processCrypto err is %@",(*err).localizedDescription);
    return result;
}
- (NSData *)engineDoFinal:(NSData *)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen err:(NSError *__autoreleasing *)err {
    if (input == nil || inputOffset < 0){
        NSLog(@"engineDoFinal: input or inputoffset is invalid");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR  errorMessage:@"engineDoFinal: input or inputoffset is invalid"];
        return nil;
    }
    return [self getOutput:input offset:inputOffset length:inputLen error:err];
}

- (NSInteger)engineDoFinal:(NSData *)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData *__autoreleasing *)output outputOffset:(NSInteger)outputOffset err:(NSError *__autoreleasing *)err {
    NSData *data = [self getOutput:input offset:inputOffset length:inputLen error:err];
    NSInteger len = (int)data.length;
    if (len + outputOffset > (*output).length){
        NSLog(@"engineDoFinal: output length not enough");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_OBJERR errorMessage:@"engineDoFinal: output length not enough"];
    }
    unsigned char *dataBytes =(unsigned char*)(*output).bytes;
    int length = (int)(*output).length;
    memcpy(dataBytes+outputOffset, (unsigned char *)data.bytes, len);
    *output = [NSData dataWithBytes:dataBytes length:length];
    return len;
}

- (NSInteger)engineDoFinal:(NSData *)input output:(NSData *__autoreleasing *)output err:(NSError *__autoreleasing *)err {
    NSData *data = [self getOutput:input offset:0 length:input.length error:err];
    *output = data;
    return data.length;
    return 0;
}

- (NSInteger)engineGetBlockSize {
    return 0;
}

- (NSData *)engineGetIV {
    return nil;
}

- (NSInteger)engineGetKeySize:(id<Key>)key err:(NSError *__autoreleasing *)err {
    return 0;
}

- (NSInteger)engineGetOutputSize:(NSInteger)inputLen {
    return 0;
}

- (id<AlgorithmParameterSpec>)engineGetParameters {
    return nil;
}

- (void)engineInit:(NSInteger)opmode key:(id<Key>)key params:(id<AlgorithmParameterSpec>)params random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
}

- (void)engineInit:(NSInteger)opmode key:(id<Key>)key random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
    self.secureCore = [SimpleSecureCore getinstance];
    self.device = [self.secureCore getDefaultDevice];

    switch (opmode) {
        case ENCRYPT_MODE:
            if ([key isMemberOfClass:[SM2PublicKey class]]){
                [self.sm2Engine encryptInitializeWithKey:(SM2PublicKey*)key device:self.device];
                break;
            }
            if (err != nil){
                NSLog(@"engineInit: can not support key type");
                *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineInit: can not support key type"];
            }
            break;
        case DECRYPT_MODE:
            if ([key isMemberOfClass:[SM2PrivateKey class]]){
                self.app = [self.secureCore getDefaultApplication];
                self.con =(SCContainer*) [self.app SKF_OpenContainer:[(SM2PrivateKey*)key getPrivateKeyAlias] err:err];
                if (*err != nil){
                    NSLog(@"engineInit: can not find privateKey");
                    *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineInit: can not find privateKey"];
                    break;
                }
                [self.sm2Engine decryptInitializeWithSimplecore:self.secureCore container:self.con];
                break;
            }
            if ([key isMemberOfClass:[SM2KeyPair class]]){
                SM2KeyPair *forImport = (SM2KeyPair*)key;
                ResultCode rs = [self.secureCore importEccKeyPair:[forImport getPrivateAlias] publicKey:[forImport getPublicKey] privateKey:[forImport getPrivateKey]];
                if (rs == SAR_CONTAINERALREADYEXIST){
                    NSLog(@"engineInit: PrivateKeyAlias already exists");
                    *err = [ErrorUtil geterrorWithCode:SAR_CONTAINERALREADYEXIST errorMessage:@"engineInit: PrivateKeyAlias already exists"];
                    break;
                }
                if (rs != SAR_OK){
                    NSLog(@"engineInit: importEccKeyPair err is %@",[resultCode toString:rs]);
                    if (err != nil)
                       *err = [ErrorUtil geterrorWithCode:SAR_FAIL errorMessage:@"engineInit: importEccKeyPair err"];
                    break;
                }
            }
            NSLog(@"cannot support this key type");
            if (err != nil)
                *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"cannot support this key type"];
            break;
        default:
            NSLog(@"unknown opmode");
            if (err != nil)
                *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"unknown opmode"];
            break;
    }
}

- (void)engineInitWithParam:(NSInteger)opmode key:(id<Key>)key params:(AlgorithmParameters *)params random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {

}

- (void)engineSetMode:(NSString *)mode err:(NSError *__autoreleasing *)err {
    if (mode == nil){
        NSLog(@"engineSetMode: mode is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineSetMode: mode is nil"];
        return ;
    }
    mode = [mode uppercaseString];
    if ([mode isEqualToString:@"NONE"]){
        NSLog(@"engineSetMode:can not support mode");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"engineSetMode:can not support mode"];
        return ;
    }
}

- (void)engineSetPadding:(NSString *)padding err:(NSError *__autoreleasing *)err {
    if (padding == nil){
        NSLog(@"engineSetPadding: padding is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineSetPadding: padding is nil"];
        return ;
    }
    padding = [padding uppercaseString];
    if ([padding isEqualToString:@"NONE"]){
        NSLog(@"engineSetPadding:can not support padding");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"engineSetMode:can not support padding"];
        return ;
    }
}

- (id<Key>)engineUnwrap:(NSData *)wrappedKey wrappedKeyAlgorithm:(NSString *)wrappedKeyAlgorithm wrappedKeyType:(NSInteger)wrappedKeyType err:(NSError *__autoreleasing *)err {
    return nil;
}

- (NSData *)engineUpdate:(NSData *)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen err:(NSError *__autoreleasing *)err {
    return nil;
}

- (NSInteger)engineUpdate:(NSData *)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData *__autoreleasing *)output outputOffset:(NSInteger)outputOffset err:(NSError *__autoreleasing *)err {
    return 0;
}

- (NSInteger)engineUpdate:(NSData *)input output:(NSData *__autoreleasing *)output err:(NSError *__autoreleasing *)err {
    return 0;
}

- (NSData *)engineWrap:(id<Key>)key err:(NSError *__autoreleasing *)err {
    return 0;
}

@end
