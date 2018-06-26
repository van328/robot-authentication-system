//
//  Signature.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/28.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "Signature.h"
#import "SignatureSpi.h"
#import "SKF_SM2Signer.h"
#import "ErrorUtil.h"
static int VERIFY = 3;
static int SIGN = 2;
static int UNINITIALIZED = 0;

@interface Signature()
@property(nonatomic,strong)id<SignatureSpi> signerSpi;
@property(nonatomic,strong)NSString *transformation;
@property(nonatomic,assign)NSInteger State;
@end
@implementation Signature
+(Signature*)getInstanceWithProvider:(NSString*)transformation provider:(NSString*)provider err:(NSError**)err{
     if ([transformation isEqualToString:@"SM2"]&& [provider isEqualToString:@"SC"]){
        id<SignatureSpi> sm2 = [[SKF_SM2Signer alloc]init];
        return [[Signature alloc]initWithSpi:sm2 transformation:transformation];
    }
    return nil;
    
}

-(instancetype)initWithSpi:(id<SignatureSpi>)signerSpi transformation:(NSString*)transformation{
    if (signerSpi == nil || transformation == nil)
        return nil;
    if (self = [super init]){
        self.signerSpi = signerSpi; 
        self.transformation = transformation;
    }
    return self;
}

-(void)initVerify:(id<PublicKey>) publicKey err:(NSError**)err{
    [self.signerSpi engineInitVerify:publicKey err:err];
    self.State = VERIFY;
}
-(void)initSign:(id<PrivateKey>) privateKey err:(NSError**)err{
    [self.signerSpi engineInitSign:privateKey err:err];
    self.State = SIGN;
}
-(void)initSign:(id<PrivateKey>)privateKey random:(SecureRandom*)random err:(NSError**)err{
    [self.signerSpi engineInitSign:privateKey random:random err:err];
    self.State = SIGN;
}
-(NSData*)sign:(NSError**)err{
    if (self.State == SIGN){
        return [self.signerSpi engineSign:err];
    }else{
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"object not initialized"];
    }
    return nil;
}

//engine未实现
-(NSInteger)sign:(NSData*)outbuf offset:(NSInteger)offset len:(NSInteger)len err:(NSError**)err{
    if (outbuf == nil){
        NSLog(@"sign: no output buffer given");
        if (err != nil) {
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"sign: no output buffer given"];
        }
        return 0;
    }
    if (offset < 0 || len < 0){
        NSLog(@"sign: offset or len is less than 0");
        if (err != nil) {
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"sign: offset or len is less than 0"];
        }
        return 0;
    }
    if (outbuf.length - offset < len){
        NSLog(@"sign: output buffer too samll for specified offset and length");
        if (err != nil) {
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"sign: output buffer too samll for specified offset and length"];
        }
        return 0;
    }
    if (self.State != SIGN){
         NSLog(@"sign: object not initialized for signing");
        if (err != nil) {
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"sign: object not initialized for signing"];
        }
        return 0;
    }
    return [self.signerSpi engineSign:outbuf offset:offset len:len err:err];
}
-(BOOL)verify:(NSData*)signature err:(NSError**)err{
    if (self.State == VERIFY){
        return [self.signerSpi engineVerify:signature err:err];
    }else{
        if (err != nil){
            NSLog(@"verify: object not initilized for verifiy");
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"verify: object not initilized for verifiy"];
        }
    }
    return NO;
}

//engine未实现
-(BOOL)verify:(NSData*)signature offset:(NSInteger)offset length:(NSInteger)length err:(NSError**)err{
    if (self.State == VERIFY){
        if (signature == nil){
            NSLog(@"verify: signatue is nil");
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"verify: signatue is nil"];
            return NO;
        }
        if (offset < 0 || length < 0){
            NSLog(@"verify: offset or len is less than 0");
            if (err != nil) {
                *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"verify: offset or len is less than 0"];
            }
            return NO;
        }
        if (signature.length - offset < length){
            NSLog(@"verify: signature too samll for specified offset and length");
            if (err != nil) {
                *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"verify: signature too samll for specified offset and length"];
            }
            return NO;
        }
        return [self.signerSpi engineVerify:signature offset:offset len:length err:err];
    }else{
        if (err != nil){
           NSLog(@"verify: object not initialized for verify");
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"verify: object not initialized for verify"];
        }
    }
    return NO;
}
-(void)updata:(Byte)b err:(NSError**)err{
    if (self.State == VERIFY || self.State == SIGN){
        [self.signerSpi engineUpdate:b err:err];
    }else{
        if (err != nil){
            NSLog(@"updata: object not initialized ");
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"updata: object not initialized "];
        }
    }
}
-(void)updataWithData:(NSData*)data err:(NSError**)err{
    if (self.State == VERIFY || self.State == SIGN){
        if (data == nil){
            NSLog(@"updata: data is nil");
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"updata: data is nil"];
        }
        [self.signerSpi engineUpdate:data off:0 len:data.length err:err];
    }else{
        if (err != nil){
            NSLog(@"object not initialized");
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"object not initialized"];
        }
    }
}
-(void)updata:(NSData*)data off:(NSInteger)off len:(NSInteger)len err:(NSError**)err{
    if (self.State == VERIFY || self.State == SIGN){
        if (data == nil){
            NSLog(@"updata: data is nil");
            *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"updata: data is nil"];
        }
        if (off < 0 || len < 0){
            NSLog(@"updata: offset or len is less than 0");
            if (err != nil) {
                *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"updata: offset or len is less than 0"];
            }
        }
        if (data.length - off < len){
            NSLog(@"updata: data too samll for specified offset and length");
            if (err != nil) {
                *err = [ErrorUtil geterrorWithCode:SAR_INVALIDPARAMERR errorMessage:@"updata: data too samll for specified offset and length"];
            }
        }
        [self.signerSpi engineUpdate:data off:off len:len err:err];
    }else{
        if (err != nil){
            NSLog(@"object not initialized");
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"object not initialized"];
        }
    }
}
-(NSString*)getAlgorithm{
    return self.getAlgorithm;
}
-(void)setParameter:(NSString*)param value:(NSObject*)value err:(NSError**)err{
    [self.signerSpi engineSetParameter:param value:value];
}
-(void)setParameter:(id<AlgorithmParameterSpec>)params err:(NSError**)err{
    [self.signerSpi engineSetParameter:params err:err];
}
-(AlgorithmParameters*)getParameters:(NSError**)err{
    return [self.signerSpi engineGetParameters:err];
}

@end
