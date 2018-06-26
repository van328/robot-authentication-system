//
//  SM2KeyPairParameter.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AlgorithmParameterSpec.h"
@interface SM2KeyPairParameter : NSObject<AlgorithmParameterSpec>
/**
 获取SM2密钥对参数实例

 @param KeyPairAlias 密钥对别名
 @return SM2密钥对参数实例
 */
-(instancetype)initWithAlias:(NSString *)KeyPairAlias;
/**
 获取密钥对别名

 @return 密钥对别名
 */
-(NSString *)getKeyPairAlias;
/**
 设置密钥对别名

 @param KeyPairAlias 密钥对别名
 */
-(void)setKeyPairAlias:(NSString *)KeyPairAlias;
@end
