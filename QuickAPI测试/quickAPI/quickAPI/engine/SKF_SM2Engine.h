//
//  SKF_SM2Engine.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Key.h"
@protocol ISignKey;
@protocol IContainer;
@class SimpleSecureCore;
@class SecureCoreDevice;
@interface SKF_SM2Engine : NSObject
/**
 签名初始化

 @param core 安全核心库
 @param container 容器
 @return 是否初始化成功
 */
-(BOOL)signatureInitializeWithSimplecore:(SimpleSecureCore *)core container:(id<ISignKey,IContainer>)container;
/**
 解密初始化
 
 @param core 安全核心库
 @param container 容器
 @return 是否初始化成功
 */
-(BOOL)decryptInitializeWithSimplecore:(SimpleSecureCore *)core container:(id<ISignKey,IContainer>)container;

/**
 加密初始化

 @param key 密钥
 @param device 设备
 @return 是否初始化成功
 */
-(BOOL)encryptInitializeWithKey:(id<Key>)key device:(SecureCoreDevice*)device;
/**
 签名验证初始化

 @param key 密钥
 @param device 设备
 @return 是否初始化成功
 */
-(BOOL)verifyInitializeWithKey:(id<Key>)key device:(SecureCoreDevice*)device;
/**
 处理加密或解密（具体处理方式由初始化方法来决定）

 @param input 输入数据
 @param offset 输入数据偏移量
 @param length 加密的输入数据长度
 @param err 错误码
 @return 明文或密文（如果失败返回nil）
 */
-(NSData *)processCrypto:(NSData *)input offset:(NSInteger)offset length:(NSInteger)length error:(NSError **)err;
/**
 处理解密
 
 @param input 输入数据
 @param offset 输入数据偏移量
 @param length 加密的输入数据长度
 @param err 错误码
 @return 明文（如果失败返回nil）
 */
-(NSData *)decryptWithCipher:(NSData *)input offset:(NSInteger)offset length:(NSInteger)length error:(NSError **)err;
/**
 处理加密
 
 @param input 输入数据
 @param offset 输入数据偏移量
 @param length 加密的输入数据长度
 @param err 错误码
 @return 密文（如果失败返回nil）
 */
-(NSData *)encryptWithPlain:(NSData *)input offset:(NSInteger)offset length:(NSInteger)length error:(NSError **)err;
/**
 签名

 @param data 待签名数据
 @param err 错误信息
 @return 签名结果，如果签名失败返回nil;
 */
-(NSData *)processSignature:(NSData *)data error:(NSError **)err;
@end
