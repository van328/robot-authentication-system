//
//  ISessionKey.h
//  sctest_morekey
//
//  Created by SecureChip on 2017/12/28.
//  Copyright © 2017年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IElement.h"
#import "resultCode.h"
#import "IMac.h"
@class BlockCipherParam;
@protocol ISessionKey <IElement>
/**
 * 对称加密初始化
 *
 * @param encryptParam 对称算法参数
 * @return 结果码
 */
-(ResultCode)SKF_EncryptInit:(BlockCipherParam*)encryptParam;
/**
 * 计算对称加密，并输出结果
 *
 * @param data 明文
 * @return 密文
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_Encrypt:(NSData*)data err:(NSError**)err;
/**
 * 计算对称加密
 *
 * @param data 明文
 * @return 密文
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_EncryptUpdate:(NSData*)data err:(NSError**)err;
/**
 * 结束对称加密
 *
 * @return 密文
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_EncryptFinal:(NSError**)err;
/**
 * 对称解密初始化
 *
 * @param decryptParam 对称解密参数
 * @return 结果码
 */
-(ResultCode)SKF_DecryptInit:(BlockCipherParam*)decryptParam;
/**
 * 计算对称解密
 *
 * @param data 密文
 * @return 明文
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_Decrypt:(NSData*)data err:(NSError**)err;
/**
 计算对称解密

 @param data 密文
 @param err 错误原因
 @return 明文
 */
-(NSData*)SKF_DecryptUpdate:(NSData *)data err:(NSError **)err;
/**
 * 结束对称解密
 *
 * @return 明文
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_DecryptFinal:(NSError**)err;
/**
 * 初始化消息鉴别码计算
 *
 * @param macParam 对称算法参数
 * @return 消息鉴别码接口
 * @throws SecureCoreException 运算中的异常
 */
-(id<IMac>)SKF_MacInit:(BlockCipherParam*)macParam err:(NSError**)err;



@end
