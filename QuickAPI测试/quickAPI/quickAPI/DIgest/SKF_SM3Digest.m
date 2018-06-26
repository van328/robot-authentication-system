//
//  SKF_SM3Digest.m
//  quickAPI
//
//  Created by SecureChip on 2018/1/30.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SKF_SM3Digest.h"
#import <MultiKey/MultiKey.h>
#import "SimpleSecureCore.h"
#define SM3Digest_Length 32
@interface SKF_SM3Digest()
@property(nonatomic,assign)Algorithm mAlgorithm;
@property(nonatomic,strong)SecureCoreDevice *device;
@property(nonatomic,strong)id<IHash> mhash;
@property(nonatomic,strong)SimpleSecureCore *msimpleSecureCore;
@end
@implementation SKF_SM3Digest
- (instancetype)init
{
    self = [super initWithAlg:@"SM3"];
    if (self) {
        self.msimpleSecureCore = [SimpleSecureCore getinstance];
        self.device = [self.msimpleSecureCore getDefaultDevice];
        self.mhash = nil;
        self.mAlgorithm = SGD_SM3;
        NSError *err = nil;
        [self engineReset:&err];
        if (err != nil){
            NSLog(@"SKF_SM3Digest init failed, err is %@",err.localizedDescription);
            return nil;
        }
    }
    return self;
}
- (NSInteger)engineGetDigestLength {
    return SM3Digest_Length;
}
- (void)engineReset:(NSError *__autoreleasing *)err {
    self.mhash = [self.device SKF_DigestInit:self.mAlgorithm pubKeyBlob:nil ID:nil err:err];
    if (err != nil && *err != nil){
        NSLog(@"SKF_DigestInit: SKF_DigestInit err is %@",(*err).localizedDescription);
    }
}
- (NSInteger)engineUpdate:(Byte)input {
    Byte inputArray[1] = {input};
    NSData *data = [NSData dataWithBytes:inputArray length:1];
    return [self engineUpdate:data offset:0 len:1];
}
- (NSInteger)engineUpdateWithData:(NSData *)input {
    ResultCode ret = [self.mhash SKF_DigestUpdate:input];
    if (ret != SAR_OK)
        NSLog(@"engineUpdateWithData: engineUpdateWithData is failed,err is %@",[resultCode toString:ret]);
    return ret;
    
}
- (NSInteger)engineUpdate:(NSData *)input offset:(NSInteger)offset len:(NSInteger)len {
    NSRange range = NSMakeRange(offset, len);
    NSData *data = [input subdataWithRange:range];
    ResultCode ret = [self.mhash SKF_DigestUpdate:data];
    if (ret != SAR_OK)
        NSLog(@"SKF_DigestUpdate: SKF_DigestUpdate is failed,err is %@",[resultCode toString:ret]);
    return ret;
}
- (NSData *)engineDigest:(NSError *__autoreleasing *)err {
    NSData *data = [self.mhash SKF_DigestFinal:err];
    if (err != nil && *err != nil){
        NSLog(@"SKF_DigestFinal: SKF_DigestFinal err is %@",(*err).localizedDescription);
    }
    return data;
}

@end
