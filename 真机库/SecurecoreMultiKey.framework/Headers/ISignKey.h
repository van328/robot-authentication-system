//
//  ISignKey.h
//  sctest_morekey
//
//  Created by SecureChip on 2017/12/28.
//  Copyright © 2017年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "resultCode.h"
@class ServerInfo;
@class ECCPublicKeyBlob;
/**
 * Created by Nick on 2017/11/14.
 * 协作签名密钥
 */
@protocol ISignKey <NSObject>
/**
 * 获取签名密钥对的ID
 *
 * @return 密钥对的ID，空字符串表示密钥不存在
 */
-(NSString*)getSignKeyID;
/**
 * 修改签名密钥对的PIN码
 *
 * @param oldPIN 旧PIN码
 * @param newPIN 新PIN
 * @return 结果码
 */
-(ResultCode)changeSignKeyPIN:(NSString*)oldPIN  newPIN:(NSString*)newPIN;
/**
 * 恢复签名密钥对
 *
 * @param pin   PIN码
 * @param keyID 密钥ID
 * @return 结果码
 */
-(ResultCode)restoreSignKey:(NSString*)pin keyID:(NSString*)keyID;
/**
 * 设置授权信息
 *
 * @param appID     应用ID
 * @param appSecret 应用授权秘密信息
 * @param list      协作服务器列表
 */
-(ResultCode)setServerAuthInfo:(NSString*)appID appSecret:(NSString*)appSecret list:(NSArray<ServerInfo *>*) list;
/**
 * 生成拆分的签名密钥对
 *
 * @param pin        保护签名私钥的PIN码
 * @param alg        算法标识
 * @param pubKeyBlob 公钥（OUT）
 * @param appID      应用ID
 * @param appSecret  应用授权秘密信息
 * @param list       协作服务器列表
 * @return 结果码
 */
-(ResultCode)SKF_GenECCKeyPair:(NSString*)pin alg:(long)alg appID:(NSString*)appID appSecret:(NSString*)appSecret list:(NSArray<ServerInfo *>*) list pubKeyBlob:(ECCPublicKeyBlob**)pubKeyBlob;
/**
 * 备份本地签名密钥对的信息
 *
 * @return 备份的数据
 * @throws SecureCoreException 异常
 */
-(NSData*)backupSignKey:(NSError**)err;
/**
 * 恢复本地签名密钥对的信息
 *
 * @param pin  用户PIN码
 * @param data 备份的数据
 * @return 结果码
 */
-(ResultCode)restoreSignKey:(NSString*)pin data:(NSData*)data;
/**
 * 使用签名密钥对中的私钥解密
 * @param pin PIN码
 * @param cipherBlob 密文
 * @return 明文
 */
-(NSData*)decryptBySignKey:(NSString*)pin cipherBlob:(ECCCipherBlob *)cipherBlob err:(NSError**)err;
/**
 * 从服务器获取重置签名密钥PIN码的数据
 * @return 重置PIN码的数据
 * @throws SecureCoreException 异常
 */
-(NSData*)getSignKeyPINInfoCipher:(NSError**)err;
/**
 * 重置签名密钥PIN码
 * @param pinInfo 重置PIN码的数据
 * @param newPIN 新的PIN码
 * @return 结果码
 */
-(ResultCode) resetSignKeyPIN:(NSData*)pinInfo newPIN:(NSString*)newPIN;



@end
