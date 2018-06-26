//
//  SKF_SM4Cipher.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/6.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SKF_SM4Cipher.h"
#import <MultiKey/MultiKey.h>
#import "ErrorUtil.h"
#import "Key.h"
#import "SimpleSecureCore.h"
#import "CipherMode.h"
#import "IvParameterSpec.h"
#import "AlgorithmParameters.h"
#define BLOCK_SIZE 16
@interface SKF_SM4Cipher()
@property(nonatomic,assign)Algorithm algName;
@property(nonatomic,assign)NSInteger PaddingType;
@property(nonatomic,strong)NSData *IV;
@property(nonatomic,strong)AlgorithmParameters *mparameters;
@property(nonatomic,assign)NSInteger opmode;
@property(nonatomic,strong)SimpleSecureCore *secureCore;
@property(nonatomic,strong)SecureCoreDevice *device;
@property(nonatomic,strong)SCContainer *con;
@property(nonatomic,strong)SCSession *sessionKey;
@end
@implementation SKF_SM4Cipher

- (NSData *)engineDoFinal:(NSData *)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen err:(NSError *__autoreleasing *)err {
    NSData *data = [input subdataWithRange:NSMakeRange(inputOffset, inputLen)];
    NSMutableData *output = [NSMutableData new];
    if (self.opmode == ENCRYPT_MODE){
        NSData *cipher1 = [self.sessionKey SKF_EncryptUpdate:data err:err];
        NSData *cipher2 = [self.sessionKey SKF_EncryptFinal:err];
        if (cipher2 != nil){
            [output appendData:cipher1];
            [output appendData:cipher2];
        }else
            return nil;
        
    }else if (self.opmode == DECRYPT_MODE){
        NSData *plain1 = [self.sessionKey SKF_DecryptUpdate:data err:err];
        NSData *plain2 = [self.sessionKey SKF_DecryptFinal:err];
        if (plain1 != nil && plain2 != nil){
            [output appendData:plain1];
            [output appendData:plain2];
        }else
            return nil;
        
        
    }else{
        NSLog(@"engineDoFinal: invalid opmode");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineDoFinal: invalid opmode"];
        return nil;
    }
    
    return output;
}

- (NSInteger)engineDoFinal:(NSData *)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData **)output outputOffset:(NSInteger)outputOffset err:(NSError *__autoreleasing *)err {
    NSData *result = [self engineDoFinal:input inputOffset:inputOffset inputLen:inputLen err:err];
    NSInteger len = (int)result.length;
    if (len + outputOffset > (*output).length){
        NSLog(@"engineDoFinal: output length not enough");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineDoFinal: output length not enough"];
        return 0;
    }
    unsigned char *dataBytes =(unsigned char*)(*output).bytes;
    int length = (int)(*output).length;
    memcpy(dataBytes+outputOffset, (unsigned char *)result.bytes, len);
    *output = [NSData dataWithBytes:dataBytes length:length];
    return len;
}

- (NSInteger)engineDoFinal:(NSData *)input output:(NSData **)output err:(NSError *__autoreleasing *)err {
    return [self engineDoFinal:input inputOffset:0 inputLen:input.length output:output outputOffset:0 err:err];
}

- (NSInteger)engineGetBlockSize {
    return BLOCK_SIZE;
}

- (NSData *)engineGetIV {
    return self.IV;
}

- (NSInteger)engineGetKeySize:(id<Key>)key err:(NSError *__autoreleasing *)err {
    if (err != nil)
        *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"engineGetKeySize: not support yet"];
    return 0;
}

- (NSInteger)engineGetOutputSize:(NSInteger)inputLen {
    NSInteger size = inputLen - inputLen % BLOCK_SIZE;
    return size;
}

- (AlgorithmParameters *)engineGetParameters {
    return self.mparameters;
}

- (void)engineInit:(NSInteger)opmode key:(id<Key>)key params:(id<AlgorithmParameterSpec>)params random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
    if([params isMemberOfClass:[IvParameterSpec class]]){
        IvParameterSpec *p = (IvParameterSpec *)params;
        NSData *ivData = [p getIv];
        if(ivData.length != BLOCK_SIZE){
            if(err!=nil)
                *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineInit: invalid param"];
            return;
        }
        self.IV = ivData;
        [self engineInit:opmode key:key random:random err:err];
    }else{
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineInit: invalid param"];
        return;
    }
    
}

- (void)engineInit:(NSInteger)opmode key:(id<Key>)key random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
    if (key == nil || random == nil){
        NSLog(@"engineInit: key or random is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_OBJERR errorMessage:@"engineInit: key or random is nil"];
        return;
    }
    if ([key getEncoded].length != BLOCK_SIZE){
        NSLog(@"engineInit: key length is err");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineInit: key length is err"];
        return;
    }
    self.opmode = opmode;
    self.secureCore = [SimpleSecureCore getinstance];
    self.device = [self.secureCore getDefaultDevice];
    self.con = [self.secureCore getDefaultContainer];
    ECCCipherBlob *cipherBlob = [ECCCipherBlob new];
    ResultCode rs = [self.device SKF_ExtECCEncrypt:[self.secureCore getPublicKey:false] plainText:[key getEncoded] cipherBlob:&cipherBlob];
    if (rs != SAR_OK){
        NSLog(@"engineInit: SKF_ExtECCEncrypt err is %@",[resultCode toString:rs]);
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:rs errorMessage:@"engineInit: SKF_ExtECCEncrypt err"];
        return;
    }
    self.sessionKey = [self.con SKF_ImportSessionKey:[self.secureCore getDefaultPIN] alg:self.algName wrapedData:[cipherBlob toByteArray] err:err];
    if ((err!=nil&&*err != nil)||self.sessionKey == nil){
        
        NSLog(@"engineInit: SKF_ImportSessionKey err is %@",(*err).localizedDescription);
        return;
    }
    BlockCipherParam *cipherParam = [BlockCipherParam new];
    [cipherParam setiv:self.IV];
    [cipherParam setPaddingType:self.PaddingType];
    if (opmode == ENCRYPT_MODE){
        rs = [self.sessionKey SKF_EncryptInit:cipherParam];
        if (rs != SAR_OK){
            NSLog(@"engineInit: SKF_EncryptInit failed, err is %@",[ErrorUtil geterrorWithCode:rs errorMessage:@"engineInit: SKF_EncryptInit failed"]);
            if(err!=nil)
                *err = [ErrorUtil geterrorWithCode:rs errorMessage:@"engineInit: SKF_EncryptInit failed"];
            return;
        }
    }else if (opmode == DECRYPT_MODE){
        rs = [self.sessionKey SKF_DecryptInit:cipherParam];
        if (rs != SAR_OK){
            NSLog(@"engineInit: SKF_DecryptInit failed, err is %@",[ErrorUtil geterrorWithCode:rs errorMessage:@"engineInit: SKF_DecryptInit failed"]);
            if(err!=nil)
                *err = [ErrorUtil geterrorWithCode:rs errorMessage:@"engineInit: SKF_DecryptInit failed"];
            return;
        }
    }else{
        NSLog(@"engineInit: invalid opmode");
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTALG errorMessage:@"engineInit: invalid opmode"];
        return;
    }
}

- (void)engineSetMode:(NSString *)mode err:(NSError *__autoreleasing *)err{
    if (mode == nil){
        NSLog(@"engineSetMode: mode is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_OBJERR errorMessage:@"engineSetMode: mode is nil"];
        return;
    }
    mode = [mode uppercaseString];
    if ([mode isEqualToString:@"ECB"] == YES){
        self.algName = SGD_SM4_ECB;
        if (err != nil)
            *err = nil;
    }else if ([mode isEqualToString:@"CBC"]){
        self.algName = SGD_SM4_CBC;
        if (err != nil)
            *err = nil;
        
    }else{
        NSLog(@"engineSetMode: mode is not supported");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTALG errorMessage:@"engineSetMode: mode is not supported"];
    }
    return;
}

- (void)engineSetPadding:(NSString *)padding err:(NSError *__autoreleasing *)err{
    if (padding == nil){
        NSLog(@"engineSetPadding: padding is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_OBJERR errorMessage:@"engineSetPadding: padding is nil"];
        return;
    }
    padding = [padding uppercaseString];
    if ([padding isEqualToString:@"NOPADDING"]){
        self.PaddingType = 0;
        if (err != nil)
            *err = nil;
    }else if ([padding isEqualToString:@"PKCS5PADDING"]){
        self.PaddingType = 1;
        if (err != nil)
            *err = nil;
    }else{
        NSLog(@"engineSetPadding: padding mode is not supported");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineSetPadding: padding mode is not supported"];
    }
}

- (id<Key>)engineUnwrap:(NSData *)wrappedKey wrappedKeyAlgorithm:(NSString *)wrappedKeyAlgorithm wrappedKeyType:(NSInteger)wrappedKeyType err:(NSError *__autoreleasing *)err {
    if (err != nil)
        *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"engineUnwrap: not support yet"];
    return nil;
}

- (NSData *)engineUpdate:(NSData *)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen err:(NSError**)err{
    NSData *data = [input subdataWithRange:NSMakeRange(inputOffset, inputLen)];
    NSData * result = nil;
    if(self.opmode == ENCRYPT_MODE){
        result = [self.sessionKey SKF_EncryptUpdate:data err:err];
    }else{
        result = [self.sessionKey SKF_DecryptUpdate:data err:err];
    }
    return result;
    
}

- (NSInteger)engineUpdate:(NSData *)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData **)output outputOffset:(NSInteger)outputOffset err:(NSError *__autoreleasing *)err {
    NSData *outData = [self engineUpdate:input inputOffset:inputOffset inputLen:inputLen err:err];
    int length = (int)outData.length;
    if(length+outputOffset>(*output).length){
        if(err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"engineUpdate: invalid param"];
        return 0;
    }
    unsigned char *dataBytes =(unsigned char*)(*output).bytes;
    int len = (int)(*output).length;
    memcpy(dataBytes+outputOffset, (unsigned char *)outData.bytes, length);
    *output = [NSData dataWithBytes:dataBytes length:len];
    return length;
    
    
}

- (NSInteger)engineUpdate:(NSData *)input output:(NSData **)output err:(NSError *__autoreleasing *)err{
    return [self engineUpdate:input inputOffset:0 inputLen:input.length output:output outputOffset:0 err:err];
}

- (NSData *)engineWrap:(id<Key>)key err:(NSError *__autoreleasing *)err {
    if (err != nil)
        *err = [ErrorUtil geterrorWithCode:SAR_NOTSUPPORTYETERR errorMessage:@"engineWrap: not supported yet"];
    return nil;
}

- (void)engineInitWithParam:(NSInteger)opmode key:(id<Key>)key params:(AlgorithmParameters *)params random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
}



@end
           
