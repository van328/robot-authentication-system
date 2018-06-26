//
//  IDevice.h
//  sctest_morekey
//
//  Created by SecureChip on 2017/12/28.
//  Copyright © 2017年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "resultCode.h"
#import "IHash.h"
#import "IApplication.h"
@class DeviceInfo;
@class RSAPublicKeyBlob;
@class ECCPublicKeyBlob;
@class ECCCipherBlob;
@class ECCKeyPairBlob;
/**
 * 设备管理接口
 * Created by Nick on 2017/3/2.
 */

@protocol IDevice <NSObject>

//region Device interface

/**
 * 设备断开连接
 *
 * @return 结果码
 */
-(ResultCode)SKF_DisconnectDev;
/**
 * 设置设备标签
 *
 * @param label 标签
 * @return 结果码
 */
-(ResultCode)SKF_SetLabel:(NSString*)label;
/**
 * 获取设备信息
 *
 * @return 设备信息
 * @throws SecureCoreException 运算中的异常
 */
-(DeviceInfo*)SKF_GetDevInfo: (NSError**)err;
/**
 * 锁定设备
 *
 * @param timeOut 超时时间
 * @return 结果码
 */
-(ResultCode)SKF_LockDev: (NSInteger*)timeOut;
/**
 * 解锁设备
 *
 * @return 结果码
 */
-(ResultCode)SKF_UnlockDev;
/**
 * 设备命令传输
 *
 * @param command 命令
 * @return 设备响应数据
 */
-(NSData*)SKF_Transmit: (NSData*)command err:(NSError**)err;
//endregion

//region Access Control

/**
 * 修改设备认证密钥
 *
 * @param keyValue 认证密钥
 * @return 结果码
 */
-(ResultCode)SKF_ChangeDevAuthKey:(NSData*)keyValue;
/**
 * 设备对第三方应用的认证
 *
 * @param authData 认证信息
 * @return 结果码
 */
-(ResultCode)SKF_DevAuth:(NSData*)authData;
//endregion

//region Application Manage


/**
 * 枚举设备中的应用
 *
 * @param appNameList 应用名称列表
 * @return 结果码
 */
-(ResultCode)SKF_EnumApplication: (NSArray<NSString *>**)appNameList;
/**
 * 删除设备中的应用
 *
 * @param appName 应用名称
 * @return 结果码
 */
-(ResultCode)SKF_DeleteApplication:(NSString*)appName;
//endregion

/**
 * 获取随机数
 *
 * @param length 随机数长度
 * @return 结果码
 */
-(NSData*)SKF_GenRandom:(NSInteger)length;
/**
 * RSA验签（外部导入公钥）
 *
 * @param pubKeyBlob 公钥
 * @param data       被签名数据
 * @param signatureBlob  签名结果
 * @return 结果码
 */
-(ResultCode)SKF_RSAVerify:(RSAPublicKeyBlob*) pubKeyBlob data:(NSData*)data signatureBlob:(NSData*)signatureBlob;
/**
 * ECC验签（外部导入公钥）：对原始数据的杂凑值验签
 *
 * @param pubKeyBlob 公钥
 * @param hashData   原始数据的杂凑值
 * @param signatureBlob  签名结果
 * @return 结果码
 */
-(ResultCode)SKF_ECCVerify:(ECCPublicKeyBlob*)pubKeyBlob hashData:(NSData*)hashData signatureBlob:(ECCSignatureBlob*)signatureBlob;
/**
 * ECC验签（外部导入公钥）：对原始数据先计算杂凑再验签
 *
 * @param pubKeyBlob 公钥
 * @param data       原始数据
 * @param signatureBlob  签名结果
 * @return 结果码
 */
-(ResultCode)SKF_ECCHashAndVerify: (ECCPublicKeyBlob*)pubKeyBlob data:(NSData*)data signatureBlob:(ECCSignatureBlob*)signatureBlob;
/**
 * ECC外部公钥加密
 *
 * @param pubKeyBlob 公钥
 * @param plainText  明文
 * @param cipherBlob 密文
 * @return 结果码
 */
-(ResultCode)SKF_ExtECCEncrypt:(ECCPublicKeyBlob*)pubKeyBlob plainText:(NSData*)plainText cipherBlob:(ECCCipherBlob**)cipherBlob;
/**
 * 杂凑初始化
 *
 * @param alg  算法标识
 * @param pubKeyBlob 公钥
 * @param ID     身份标识
 * @return 杂凑计算接口
 */
-(id<IHash>)SKF_DigestInit:(long)alg pubKeyBlob:(ECCPublicKeyBlob*)pubKeyBlob ID:(NSData*)ID err:(NSError**)err;
/**
 * 创建应用
 *
 * @param appName 应用名称
 * @return 应用接口
 * @throws SecureCoreException 运算中的异常
 */
-(id<IApplication>) SKF_CreateApplication:(NSString*)appName err:(NSError**)err;
/**
 * 打开指定的应用
 *
 * @param appName 应用名称
 * @return 应用接口
 * @throws SecureCoreException 运算中的异常
 */
-(id<IApplication>) SKF_OpenApplication:(NSString*)appName err:(NSError**)err;
/**
 * 对安全核心设备进行初始化
 *
 * @return 结果码
 */

-(ResultCode)Initialize;
/**
 * 生成ECC密钥对
 *
 * @return 密钥对结构
 */
-(ECCKeyPairBlob*)generateECCKeyPair:(NSError**)err;
/**
 * SM2解密
 *
 * @param priKey 私钥
 * @param cipher 密文
 * @return 明文
 */
-(NSData*)SM2Decrypt:(NSData*)priKey cipher:(NSData*)cipher err:(NSError**)err;


-(BOOL) setAdminPublicKey: (ECCPublicKeyBlob*)pubKeyBlob;
@end
