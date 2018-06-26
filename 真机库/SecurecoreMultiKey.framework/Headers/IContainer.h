//
//  IContainer.h
//  sctest_morekey
//
//  Created by SecureChip on 2017/12/27.
//  Copyright © 2017年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IElement.h"
#import "IAgreement.h"
#import "ISessionKey.h"
#import "resultCode.h"
#import "SCContainerType.h"
#import "Algorithm.h"
@class RSAPublicKeyBlob;
@class ECCPublicKeyBlob;
@class EnvelopedKeyBlob;
@class ECCCipherBlob;
@class FileAttribute;
@class ECCSignatureBlob;
@protocol IContainer <IElement>

//region Container Interface

/**
 * 关闭容器
 *
 * @return 结果码
 */
-(ResultCode)SKF_CloseContainer;
/**
 * 获取容器类型
 *
 * @return 容器类型
 */
-(SCContainerType)SKF_GetContainerType;
/**
 * 导入证书
 *
 * @param signFlag 是否为签名证书
 * @param cert     证书数据
 * @return 结果码
 */
-(ResultCode)SKF_ImportCertificate:(BOOL)signFlag cert:(NSData*)cert;
/**
 * 导出证书
 *
 * @param signFlag 是否为签名证书
 * @return 证书数据
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_ExportCertificate:(BOOL)signFlag err:(NSError**)err;
//endregion

//region Cipher Service

//region RSA cipher

/**
 * 生成RSA签名密钥对
 *
 * @param bitsLen 长度
 * @param blob    公钥
 * @return 结果码
 */
-(ResultCode)SKF_GenRSAKeyPair:(NSInteger)bitsLen  blob:(RSAPublicKeyBlob**)blob;
/**
 * 导入RSA加密密钥对
 *
 * @param symAlgId      算法标识
 * @param wrappedKey    封装的密钥
 * @param encryptedData 加密数据
 * @return 结果码
 */
-(ResultCode)SKF_ImportRSAKeyPair:(long)symAlgId wrappedKey:(NSData*)wrappedKey encryptedData:(NSData*) encryptedData;
/**
 * RSA签名
 *
 * @param data 待签名数据
 * @return 签名结果
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_RSASignData:(NSData*)data err:(NSError**)err;
/**
 * RSA生成并导出会话密钥
 *
 * @param alg      算法标识
 * @param pubKeyBlob 公钥
 * @param data       会话秘钥
 * @return 会话密钥接口
 * @throws SecureCoreException 运算中的异常
 */
-(id<ISessionKey>)SKF_RSAExportSessionKey:(long)alg pubKeyBlob:(RSAPublicKeyBlob*)pubKeyBlob data:(NSData*)data err:(NSError**)err;
//endregion

//region ECC cipher

/**
 * ECC生成密钥协商参数
 *
 * @param alg      算法标识
 * @param pubKeyBlob 公钥
 * @param cipherBlob 加密数据
 * @return 会话密钥接口
 * @throws SecureCoreException 异常
 */
-(id<ISessionKey>)SKF_ECCExportSessionKey:(long)alg pubKeyBlob:(ECCPublicKeyBlob*)pubKeyBlob cipherBlob:(ECCCipherBlob**)cipherBlob err:(NSError**)err;
//endregion

/**
 * 导出公钥
 *
 * @param signFlag 是否为签名公钥
 * @return 公钥
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*) SKF_ExportPublicKey:(BOOL)signFlag err:(NSError**)err;
/**
 * 检查密钥对是否存在
 *
 * @param signFlag 是否为签名密钥对
 * @return 结果码
 */
-(ResultCode)SKF_CheckKeyPairExistence:(BOOL)signFlag;
//endregion


//region File Manage 6个

/**
 * 创建文件
 *
 * @param fileName 文件名称
 * @return 结果码
 */
-(ResultCode)SKF_CreateFile:(NSString*)fileName fileSize:(NSInteger)fileSize;
/**
 * 删除文件
 *
 * @param fileName 文件名称
 * @return 结果码
 */
-(ResultCode)SKF_DeleteFile:(NSString*)fileName;
/**
 * 枚举文件
 *
 * @param fileList 文件名称列表
 * @return 结果码
 */
-(ResultCode)SKF_EnumFiles:(NSArray<NSString *>**) fileList;
/**
 * 获取文件属性
 *
 * @param fileName 文件名称
 * @param fileInfo 文件属性
 * @return 结果码
 */
-(ResultCode)SKF_GetFileInfo:(NSString*)fileName fileInfo:(FileAttribute**) fileInfo;
//endregion

/**
 * 生成ECC签名密钥对
 *
 * @param pin        保护签名私钥的PIN码
 * @param alg        算法标识
 * @param pubKeyBlob 公钥（OUT）
 * @return 结果码
 */
-(ResultCode)SKF_GenECCKeyPair:(NSString*)pin alg:(Algorithm)alg pubKeyBlob:(ECCPublicKeyBlob**) pubKeyBlob;
/**
 * 导入ECC加密密钥对
 *
 * @param pin     PIN码
 * @param keyBlob 封装的ECC密钥对
 * @return 结果码
 */
-(ResultCode)SKF_ImportECCKeyPair:(NSString*)pin  keyBlob:(EnvelopedKeyBlob*)keyBlob;
/**
 * ECC签名：对原始数据的杂凑值进行签名
 *
 * @param pin           PIN码
 * @param hashData      原始数据的杂凑值
 * @param signatureBlob 签名结果（OUT）
 * @return 结果码
 */
-(ResultCode)SKF_ECCSignData:(NSString*)pin hashData:(NSData*)hashData signatureBlob: (ECCSignatureBlob**)signatureBlob;
/**
 * ECC签名：对原始数据计算杂凑值后再计算签名
 *
 * @param pin           PIN码
 * @param data          原始数据
 * @param signatureBlob 签名结果（OUT）
 * @return 结果码
 */
-(ResultCode)SKF_ECCHashAndSignData:(NSString*)pin data:(NSData*)data signatureBlob: (ECCSignatureBlob**)signatureBlob;
/**
 * ECC解密
 *
 * @param pin        PIN码
 * @param cipherBlob 密文
 * @return 明文
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_ECCDecrypt:(NSString*)pin cipherBlob:(ECCCipherBlob*)cipherBlob err:(NSError**)err;

/**
 * ECC产生协商数据并计算会话密钥
 *
 * @param pin                      PIN码
 * @param alg                      算法标识
 * @param sponsorECCPubKeyBlob     发起者公钥
 * @param sponsorTempECCPubKeyBlob 发起者临时公钥
 * @param tempECCPubKeyBlob        临时公钥
 * @param ID                       身份标识
 * @param sponsorID                发起者身份标识
 * @return 会话密钥接口
 * @throws SecureCoreException 运算中的异常
 */
-(id<ISessionKey>)SKF_GenerateAgreementDataAndKeyWithECC:(NSString*)pin alg:(long)alg sponsorECCPubKeyBlob:(ECCPublicKeyBlob*)
sponsorECCPubKeyBlob sponsorTempECCPubKeyBlob:(ECCPublicKeyBlob*)sponsorTempECCPubKeyBlob
                                       tempECCPubKeyBlob:(ECCPublicKeyBlob**)tempECCPubKeyBlob ID:(NSData*)ID sponsorID:(NSData*)sponsorID err:(NSError**)err;
/**
 * 导入会话密钥
 *
 * @param pin        PIN码
 * @param alg        算法标识
 * @param wrapedData 封装的数据
 * @return 会话密钥接口
 * @throws SecureCoreException 运算中的异常
 */
-(id<ISessionKey>)SKF_ImportSessionKey:(NSString*)pin alg:(long)alg wrapedData:(NSData*)wrapedData err:(NSError**)err;
/**
 * ECC生成密钥协商参数并输出
 *
 * @param alg               算法标识
 * @param tempECCPubKeyBlob 临时公钥
 * @param ID                身份标识
 * @return 密钥协商接口
 * @throws SecureCoreException 运算中的异常
 */
-(id<IAgreement>)SKF_GenerateAgreementDataWithECC:(long)alg tempECCPubKeyBlob:(ECCPublicKeyBlob**) tempECCPubKeyBlob ID:(NSData*)ID err:(NSError**)err;
/**
 * 读文件
 *
 * @param pin      PIN码
 * @param fileName 文件名称
 * @param offset   偏移值
 * @param size     读取长度
 * @return 文件数据
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_ReadFile:(NSString*)pin fileName:(NSString*)fileName offset:(NSInteger)offset size:(NSInteger)size err:(NSError**)err;
/**
 * 写文件
 *
 * @param pin      PIN码
 * @param fileName 文件名称
 * @param offset   偏移值
 * @param data     待写入数据
 * @param size     待写入数据长度
 * @return 结果码
 */
-(ResultCode)SKF_WriteFile:(NSString*)pin fileName:(NSString*)fileName offset:(NSInteger)offset data:(NSData*)data size:(NSInteger)size;

@end
