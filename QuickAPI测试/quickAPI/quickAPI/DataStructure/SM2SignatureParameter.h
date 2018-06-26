//
//  SM2SignatureParameter.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SM2SignatureParameter : NSObject
/**
 获取SM2签名密钥对实例

 @param signatureKeyPairAlias 签名密钥对别名
 @param forGenerate 是否生成密钥
 @return SM2签名密钥对实例
 */
-(instancetype)initWithAlias:(NSString *)signatureKeyPairAlias isGenerate:(BOOL)forGenerate;
/**
 获取签名密钥对别名

 @return 签名密钥对别名
 */
-(NSString *)getSignatureKeyPairAlias;
/**
 设置签名密钥对别名

 @param signatureKeyPairAlias 签名密钥对别名
 */
-(void)setSignatureKeyPairAlias:(NSString *)signatureKeyPairAlias;
@end
