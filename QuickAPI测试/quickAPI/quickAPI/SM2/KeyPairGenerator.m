//
//  KeyPairGenerator.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/26.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "KeyPairGenerator.h"
#import "SKF_SM2CipherKeyPairGenerator.h"
#import "SKF_SM2SignatureKeyPairGenerator.h"
@interface KeyPairGenerator()
@property(nonatomic,strong)NSString *algorithm;
@end
@implementation KeyPairGenerator

- (KeyPair *)generateKeyPair {
    return nil;
}

- (void)initialize:(NSInteger)keysize random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
    
}
- (void)initialize:(id<AlgorithmParameterSpec>)params err:(NSError *__autoreleasing *)err {
    [self initializeWithParam:params random:[SecureRandom new] err:err];
}

- (void)initializeWithParam:(id<AlgorithmParameterSpec>)params random:(SecureRandom *)random err:(NSError *__autoreleasing *)err {
}
+(KeyPairGenerator*)getInstance:(NSString *)algorithm provider:(NSString *)provider{
    if([algorithm isEqualToString:@"SM2Cipher"]&&[provider isEqualToString:@"SC"]){
        SKF_SM2CipherKeyPairGenerator *sm2Cipher = [SKF_SM2CipherKeyPairGenerator new];
        return sm2Cipher;
    }else if ([algorithm isEqualToString:@"SM2Signature"]&&[provider isEqualToString:@"SC"]){
        SKF_SM2SignatureKeyPairGenerator *sm2Signature = [SKF_SM2SignatureKeyPairGenerator new];
        return sm2Signature;
    }
    return nil;
}
@end
