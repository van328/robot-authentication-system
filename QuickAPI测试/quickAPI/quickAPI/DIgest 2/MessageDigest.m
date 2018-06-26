
//  MessageDigest.m
//  quickAPI
//
//  Created by SecureChip on 2018/1/30.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "MessageDigest.h"
#import <MultiKey/resultCode.h>
#import "DigestInterface.h"
#import "SKF_SM3Digest.h"
#import "ErrorUtils.h"
@interface MessageDigest()
@property (nonatomic,strong)NSString *alg;
@property (nonatomic,strong)NSString *provider;
@end
@implementation MessageDigest
-(void)reset:(NSError *__autoreleasing *)err{
    [self engineReset:err];
    if (err != nil && *err!=nil)
        NSLog(@"message digest reset is failed : err = %@",(*err).localizedDescription);
}

+(instancetype)getInstance:(NSString*)alg provider:(NSString*)provider{
    if([alg isEqualToString:@"SM3"]&&[provider isEqualToString:@"SC"]){
        return [[SKF_SM3Digest alloc]init];
    }
    return nil;
}
-(instancetype)initWithAlg:(NSString *)alg{
    if(self = [super init]){
        self.alg = alg;
    }
    return self;
}
-(void)update:(Byte)input error:(NSError *__autoreleasing *)err{
    NSInteger ret = [self engineUpdate:input];
    if(err!=nil)
        *err = (ret == SAR_OK)?nil:[ErrorUtils geterrorWithCode:ret];
    
}
-(void)updateWithData:(NSData*)input error:(NSError *__autoreleasing *)err{
    NSInteger ret =  [self engineUpdateWithData:input];
    if(err!=nil)
        *err = (ret == SAR_OK)?nil:[ErrorUtils geterrorWithCode:ret];
}
-(void)update:(NSData*)input offset:(NSInteger)offset len:(NSInteger)len error:(NSError *__autoreleasing *)err{
    NSInteger ret = SAR_OK;
    if (input == nil){
        ret = SAR_OBJERR;
        NSLog(@"update: no input buffer is given");
    }else if ((input.length - offset) < len){
        ret = SAR_INDATALENERR;
        NSLog(@"update: input buffer too short");
    }
    if (ret != SAR_OK) {
        if(err!=nil)
            *err = [ErrorUtils geterrorWithCode:ret];
        return;
    }
    [self engineUpdate:input offset:offset len:len];
    
}
-(NSData*)Digest:(NSError *__autoreleasing *)err{
    NSData *result = [self engineDigest:err];
    if (err != nil && *err != nil)
        NSLog(@" digest is failed : err = %@",(*err).localizedDescription);
    return result;
}
-(NSData*)Digest:(NSData*)input error:(NSError *__autoreleasing *)err{
    NSError *error = nil;
    [self updateWithData:input error:&error];
    if(error!=nil){
        if(err!=nil)
            *err = error;
        return nil;
    }
    
    return [self Digest:err];
}
-(NSInteger)Digest:(NSData**)buf offset:(NSInteger)offset len:(NSInteger)len error:(NSError *__autoreleasing *)err{
    NSInteger ret = SAR_OK;
    NSInteger numBytes = 0;
    if (buf==nil||*buf==nil){
        ret = SAR_OBJERR;
        NSLog(@"Digest: no output buffer is given");
    }else if (((*buf).length - offset) < len){
        ret = SAR_INDATALENERR;
        NSLog(@"Digest: output buffer too small for special offset and length");
    }
    if (ret != SAR_OK) {
        if(err!=nil)
            *err = [ErrorUtils geterrorWithCode:ret];
        return numBytes;
    }
    
    numBytes = [self engineDigest:buf offset:offset len:len err:err];
    return numBytes;
   
}

-(NSInteger)getDigestLength{
    return [self engineGetDigestLength];
}
-(NSString*)getAlgorithm{
    return self.alg;
}



- (void)engineReset:(NSError *__autoreleasing *)err {
}
- (NSInteger)engineUpdate:(Byte)input {
    return SAR_NOTSUPPORTYETERR;
}
- (NSInteger)engineUpdateWithData:(NSData *)input {
    return SAR_NOTSUPPORTYETERR;
}
- (NSInteger)engineUpdate:(NSData *)input offset:(NSInteger)offset len:(NSInteger)len {
    return SAR_NOTSUPPORTYETERR;
}

- (NSData *)engineDigest:(NSError *__autoreleasing *)err {
    return nil;
}

- (NSInteger)engineDigest:(NSData **)buf offset:(NSInteger)offset len:(NSInteger)len err:(NSError **)err {
    if(buf==nil||*buf==nil){
        if(err!=nil)
            *err = [ErrorUtils geterrorWithCode:SAR_OBJERR];
        return 0;
    }
    NSError *error = nil;
    NSData *digest = [self engineDigest:&error];
    
    if(len < digest.length||error!=nil||((*buf).length-offset<digest.length)){
        if(err!=nil)
            *err = [ErrorUtils geterrorWithCode:SAR_INDATALENERR];
        return 0;
    }
    
    unsigned char *bufBytes = (unsigned char*)(*buf).bytes;
    unsigned char *digestBytes = (unsigned char*)digest.bytes;
    memccpy(bufBytes+offset, digestBytes, 0, digest.length);
    *buf = [NSData dataWithBytes:bufBytes length:(*buf).length];
    if(err!=nil)
        *err = nil;
    return digest.length;
}
- (NSInteger)engineGetDigestLength {
    return 0;
}


@end
