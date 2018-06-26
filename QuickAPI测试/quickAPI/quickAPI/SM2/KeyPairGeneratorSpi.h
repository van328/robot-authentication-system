//
//  KeyPairGeneratorSpi.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/11.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SecureRandom.h"
#import "AlgorithmParameterSpec.h"

@class KeyPair;
@protocol KeyPairGeneratorSpi <NSObject>

/**
 生成密钥对。如果没有使用 KeyPairGenerator 接口调用初始化方法，则将使用特定于算法的默认值。每次调用此方法都将生成新的密钥对
 */
-(KeyPair*)generateKeyPair;


/**
 使用默认参数集初始化确定密钥大小的密钥对生成器

 @param keysize 密钥大小。这是特定于算法的度量（如模长度），以位数的形式指定
 @param random 生成器的随机源
 @param err 返回错误
 */

-(void)initialize:(NSInteger)keysize random:(SecureRandom*)random err:(NSError**)err;


/**
 用指定参数集合和用户提供的随机源初始化密钥对生成器

 @param params 用于生成密钥的参数集合
 @param random 生成器的随机源
 @param err 返回错误
 */
-(void)initializeWithParam:(id<AlgorithmParameterSpec>)params random:(SecureRandom*)random err:(NSError**)err;
@end
