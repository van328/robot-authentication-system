//
//  Cipher.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "Cipher.h"
#import "ErrorUtil.h"
#import <MultiKey/MultiKey.h>
#import "AlgorithmParameterSpec.h"
#import "CipherMode.h"
#import "Key.h"
#import "CipherInterface.h"
#import "SKF_SM4Cipher.h"
#import "SKF_SM2Cipher.h"
#import "SecureRandom.h"
#import "Certificate.h"
@interface Cipher()
@property (nonatomic,strong) id<CipherInterface> cipherSpi;
@property(nonatomic,assign)BOOL initialized;
@property(nonatomic,assign)NSInteger opmode;
@property(nonatomic,strong)NSString *transformation;
@end

@implementation Cipher
+(Cipher*)getInstanceWithProvider:(NSString*)transformation provider:(NSString*)provider err:(NSError**)err{
    if (([transformation isEqualToString:@"SM4/CBC/NOPADDING"]||[transformation isEqualToString:@"SM4/CBC/PKCS5PADDING"] || [transformation isEqualToString:@"SM4/ECB/NOPADDING"]||[transformation isEqualToString:@"SM4/ECB/PKCS5PADDING"]) && [provider isEqualToString:@"SC"]){
        id<CipherInterface> sm4 = [[SKF_SM4Cipher alloc]init];
        if ([transformation isEqualToString:@"SM4/CBC/NOPADDING"]){
            [sm4 engineSetMode:@"CBC" err:err];
            [sm4 engineSetPadding:@"NOPADDING" err:err];
        }else if([transformation isEqualToString:@"SM4/CBC/PKCS5PADDING"]){
            [sm4 engineSetMode:@"CBC" err:err];
            [sm4 engineSetPadding:@"PKCS5PADDING" err:err];
        }else if([transformation isEqualToString:@"SM4/ECB/NOPADDING"]){
            [sm4 engineSetMode:@"ECB" err:err];
            [sm4 engineSetPadding:@"NOPADDING" err:err];
        }else if([transformation isEqualToString:@"SM4/ECB/PKCS5PADDING"]){
            [sm4 engineSetMode:@"ECB" err:err];
            [sm4 engineSetPadding:@"PKCS5PADDING" err:err];
        }
        return [[Cipher alloc]initWithSpi:sm4 transformation:transformation];
    }else if ([transformation isEqualToString:@"SM2"]&& [provider isEqualToString:@"SC"]){
        id<CipherInterface> sm2 = [[SKF_SM2Cipher alloc]init];
        return [[Cipher alloc]initWithSpi:sm2 transformation:transformation];
    }
    return nil;
    
}

-(instancetype)initWithSpi:(id<CipherInterface>)cipherSpi transformation:(NSString*)transformation{
    if (cipherSpi == nil || transformation == nil)
        return nil;
    if (self = [super init]){
        self.cipherSpi = cipherSpi;
        self.transformation = transformation;
    }
    return self;
}
-(BOOL)checkCipherState{
    if (self.initialized == NO || (self.opmode != ENCRYPT_MODE && self.opmode != DECRYPT_MODE)){
        NSLog(@"checkCipherState: not initialized or opmode err");
        return NO;
    }
    return YES;
}

-(NSData*)doFinal:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"checkCipherState: not initialized or opmode err"];
            return nil;
        }
    }
    
    NSData *data = [self.cipherSpi engineDoFinal:nil inputOffset:0 inputLen:0 err:err];
    return data;
}

-(NSData*)doFinal:(NSData*)input err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"checkCipherState: not initialized or opmode err"];
            return nil;
        }
    }
    if (input == nil){
        NSLog(@"doFinal: input is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"doFinal: input is nil"];
        return nil;
    }
    // updateproviderifneeded
    NSData *data = [self.cipherSpi engineDoFinal:input inputOffset:0 inputLen:input.length err:err];
    
    return data;
}
-(NSInteger)doFinal:(NSData**)output outputoffset:(NSInteger)outputoffset err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"checkCipherState: not initialized or opmode err"];
            return 0;
        }
    }
    if (output == nil || *output == nil || outputoffset < 0){
        NSLog(@"doFinal: output is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"doFinal: output is nil"];
        return 0;
    }
    // updateproviderifneeded
    NSInteger len = [self.cipherSpi engineDoFinal:nil inputOffset:0 inputLen:0 output:output outputOffset:outputoffset err:err];
   
    return len;
}

-(NSData*)doFinal:(NSData*)input  inputoffset:(NSInteger)inputoffset inputLen:(NSInteger)inputLen err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"checkCipherState: not initialized or opmode err"];
            return nil;
        }
    }
    if (input == nil || inputoffset < 0 || inputLen > (input.length - inputoffset) || inputLen < 0){
        NSLog(@"doFinal: input is nil or inputoffset,inputLen is invalid ");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"doFinal: input is nil or inputoffset,inputLen is invalid "];
        return nil;
    }
    // updateproviderifneeded
    NSData *data = [self.cipherSpi engineDoFinal:input inputOffset:inputoffset inputLen:inputLen err:err];
    return data;
}

-(NSInteger)doFinal:(NSData*)input inputoffset:(NSInteger)inputoffset inputLen:(NSInteger)inputLen output:(NSData**)output err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"checkCipherState: not initialized or opmode err"];
            return 0;
        }
    }
    if (input == nil || inputoffset < 0 || inputLen > (input.length - inputoffset) || inputLen < 0 || output == nil){
        NSLog(@"doFinal: input is nil or inputoffset,inputLen is invalid ");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"doFinal: input is nil or inputoffset,inputLen is invalid "];
        return 0;
    }
    // updateproviderifneeded
    NSInteger len = [self.cipherSpi engineDoFinal:input inputOffset:inputoffset inputLen:inputLen output:output outputOffset:0 err:err];
    return len;
}
-(NSInteger)doFinal:(NSData*)input inputoffset:(NSInteger)inputoffset inputLen:(NSInteger)inputLen output:(NSData**)output outputoffset:(NSInteger)outputoffset err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"checkCipherState: not initialized or opmode err"];
            return 0;
        }
    }
    if (input == nil || inputoffset < 0 || inputLen > (input.length - inputoffset) || inputLen < 0 || outputoffset < 0 || output == nil){
        NSLog(@"doFinal: input is nil or inputoffset,inputLen,outputoffset is invalid ");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"doFinal: input is nil or inputoffset,inputLen,outputoffset is invalid "];
        return 0;
    }
    // updateproviderifneeded
    NSInteger len = [self.cipherSpi engineDoFinal:input inputOffset:inputoffset inputLen:inputLen output:output outputOffset:outputoffset err:err];
    return len;
}
-(NSInteger)doFinal:(NSData*)input output:(NSData**)output err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"checkCipherState: not initialized or opmode err"];
            return 0;
        }
    }
    if (input == nil || output == nil || *output == input  ){
        NSLog(@"doFinal: input or output is nil  ");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"doFinal: input or output is nil  "];
        return 0;
    }
    NSInteger len =  [self.cipherSpi engineDoFinal:input output:output err:err];
    return len;
}

-(NSInteger)getBlockSize{
   
    return [self.cipherSpi engineGetBlockSize];
}


-(NSData*)getIV{
    // updateproviderifneeded
    return [self.cipherSpi engineGetIV];
}
-(NSInteger)getMaxAllowedKeyLength:(NSString*)transformation err:(NSError**)err{
    if (transformation == nil){
        NSLog(@"getMaxAllowedKeyLength:transformation is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"getMaxAllowedKeyLength:transformation is nil"];
        return 0;
    }
    return INT_MAX;
}
-(id<AlgorithmParameterSpec>)getMaxAllowedParameterSpec:(NSString*)transformation err:(NSError**)err{
    if (transformation == nil){
        NSLog(@"getMaxAllowedParameterSpec:transformation is nil ");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"getMaxAllowedParameterSpec:transformation is nil "];
        return nil;
    }
    // tokenizetransformation
    return nil;
}
-(NSInteger)getOutputSize:(NSInteger)inputLen err:(NSError**)err{
    if (inputLen < 0){
        NSLog(@"getOutputSize:inputLen less than 0 ");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"getOutputSize:inputLen less than 0 "];
        return 0;
    }
    // updateproviderifneeded
    return [self.cipherSpi engineGetOutputSize:inputLen];
}
-(AlgorithmParameters*)getParameters{
    return [self.cipherSpi engineGetParameters];
}

-(void)initializeWithMode:(NSInteger)opmode certificate:(Certificate*)certificate err:(NSError**)err{
    [self initializeWithMode:opmode certificate:certificate random:[SecureRandom new] err:err];
}
-(void)initializeWithMode:(NSInteger)opmode certificate:(Certificate*)certificate random:(SecureRandom*)random err:(NSError**)err{
    if ([self checkOpmode:opmode] == NO){
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"initializeWithMode: mode err"];
        return;
    }
    if(certificate == nil || random == nil){
        NSLog(@"init: certificate or random is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"init: certificate or random is nil"];
        return;
    }
    self.initialized = YES;
   
}
-(BOOL)checkOpmode:(NSInteger)opmode{
    if (opmode < ENCRYPT_MODE || opmode > UNWRAP_MODE)
        return NO;
    return YES;
}
-(void)initializeWithMode:(NSInteger)opmode key:(id<Key>)key err:(NSError**)err{

    [self.cipherSpi engineInit:opmode key:key random:[SecureRandom new] err:err];
    if (*err == nil){
        self.initialized = YES;
        self.opmode = opmode;
    }
}

-(void)initializeWithParam:(NSInteger)opmode key:(id<Key>)key params:(id<AlgorithmParameterSpec>)params  err:(NSError**)err{
    [self.cipherSpi engineInit:opmode key:key params:params random:[SecureRandom new] err:err];
    if (*err == nil){
        self.initialized = YES;
        self.opmode = opmode;
    }
}

-(void)initializeWithParam:(NSInteger)opmode key:(id<Key>)key params:(id<AlgorithmParameterSpec>)params  random:(SecureRandom*)random err:(NSError**)err{
    [self.cipherSpi engineInit:opmode key:key params:params random:random err:err];
}

-(void)initializeWithMode:(NSInteger)opmode key:(id<Key>)key random:(SecureRandom*)random err:(NSError**)err{
    
}
//暂不实现
-(id<Key>)unwrap:(NSData*)wrappedKey wrappedKeyAlgorithm:(NSString*)wrappedKeyAlgorithm wrappedKeyType:(NSInteger)wrappedKeyType err:(NSError**)err{
    if (self.initialized == NO){
        NSLog(@"unwrap: cipher not initialized");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"unwrap: cipher not initialized"];
        return nil;
    }
    if (self.opmode != UNWRAP_MODE){
        NSLog(@"unwrap: opmode is unwrap mode");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"unwrap: opmode is unwrap mode"];
        return nil;
    }
//    if ((wrappedKeyType != SECRET_KEY)&&(wrappedKeyType != PRIVATE_KEY)&&(wrappedKeyType = PUBLIC_KEY)){
//        NSLog(@"unwrap: invalid key type");
//        if (err != nil)
//            *err = [ErrorUtils geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"unwrap: invalid key type"];
//        return nil;
//    }
    
    return [self.cipherSpi engineUnwrap:wrappedKey wrappedKeyAlgorithm:wrappedKeyAlgorithm wrappedKeyType:wrappedKeyType err:err];
}
-(NSData*)update:(NSData*)input err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"checkCipherState: not initialized or opmode err"];
            return 0;
        }
    }
    if (input == nil){
        NSLog(@"update: input is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"update: input is nil"];
        return nil;
    }
    if (input.length == 0){
        NSLog(@"update: input length is 0");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"update: input length is 0"];
        return nil;
    }
    NSData *data = [self.cipherSpi engineUpdate:input inputOffset:0 inputLen:input.length err:err];
    return data;
}
-(NSData*)update:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"cipher not initialized"];
            return 0;
        }
    }
    if (input == nil || inputOffset <0 || inputLen > (input.length - inputOffset) || inputLen < 0){
        NSLog(@"update: input is nil or inputOffset,inputLen is invalid");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"update: input is nil or inputOffset,inputLen is invalid"];
        return nil;
    }
    if (inputLen == 0){
        NSLog(@"update: input len is 0");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"update: input len is 0"];
        return nil;
    }
    NSData *data = [self.cipherSpi engineUpdate:input inputOffset:inputOffset inputLen:inputLen err:err];
    
    return data;
}
-(NSInteger)update:(NSData*)input output:(NSData**)output err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"cipher not initialized"];
            return 0;
        }
    }
    if (input == nil || output == nil || *output == input ){
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"update: input or output is nil"];
        return 0;
    }
    return [self.cipherSpi engineUpdate:input output:output err:err];
}
-(NSInteger)update:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData**)output outputOffset:(NSInteger)outputOffset err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"cipher not initialized"];
            return 0;
        }
    }
    if (input == nil || inputOffset <0 || inputLen > (input.length - inputOffset) || inputLen < 0 || output == nil || outputOffset < 0){
        NSLog(@"update: arguments is invalid");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"update: arguments is invalid"];
        return 0;
    }
    return [self.cipherSpi engineUpdate:input inputOffset:inputOffset inputLen:inputLen output:output outputOffset:outputOffset err:err];
}
-(NSInteger)update:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData**)output err:(NSError**)err{
    if ([self checkCipherState] == NO){
        if (err != nil){
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"cipher not initialized"];
            return 0;
        }
    }
    if (input == nil || inputOffset <0 || inputLen > (input.length - inputOffset) || inputLen < 0 || output == nil ){
        NSLog(@"update: arguments is invalid");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"update: arguments is invalid"];
        return 0;
    }
    return [self.cipherSpi engineUpdate:input inputOffset:inputOffset inputLen:inputLen output:output outputOffset:0 err:err];
}
@end
