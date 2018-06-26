//
//  Cipher.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AlgorithmParameterSpec.h"
#import "AlgorithmParameters.h"
#import "Key.h"
#import "SKF_SM4Cipher.h"
#import "CipherMode.h"
@class ExemptionMechanism;
@class Provider;
@class Certificate;
@class SecureRandom;
@protocol AlgorithmParameterSpec;
@interface Cipher :NSObject

/**
 结束多部分加密或解密操作（具体取决于此 Cipher 的初始化方式）。
 处理在上一次 update 操作中缓存的输入数据，其中应用了填充（如果请求）。
 结果将存储在新缓冲区中

 @param err 返回错误
 @return 包含结果的新缓冲区
 */
-(NSData*)doFinal:(NSError**)err;


/**
 按单部分操作加密或解密数据，或者结束一个多部分操作。数据将被加密或解密（具体取决于此 Cipher 的初始化方式）

 @param input 输入缓冲区
 @param err 返回错误
 @return 包含结果的新缓冲区
 */
-(NSData*)doFinal:(NSData*)input err:(NSError**)err;


/**
 结束多部分加密或解密操作（具体取决于此 Cipher 的初始化方式）

 @param output 用于保存结果的缓冲区
 @param outputoffset :output 中保存结果处的偏移量
 @param err 返回错误
 @return output 中存储的字节数
 */
-(NSInteger)doFinal:(NSData**)output outputoffset:(NSInteger)outputoffset err:(NSError**)err;


/**
 按单部分操作加密或解密数据，或者结束一个多部分操作。数据将被加密或解密（具体取决于此 Cipher 的初始化方式）

 @param input 输入缓冲区
 @param inputoffset 输入起始处的偏移量
 @param inputLen 输入长度
 @param err 返回错误
 @return 包含结果的新缓冲区
 */
-(NSData*)doFinal:(NSData*)input  inputoffset:(NSInteger)inputoffset inputLen:(NSInteger)inputLen err:(NSError**)err;


/**
 按单部分操作加密或解密数据，或者结束一个多部分操作。数据将被加密或解密（具体取决于此 Cipher 的初始化方式）

 @param input 输入缓冲区
 @param inputoffset 输入起始处的偏移量
 @param inputLen 输入长度
 @param output 保存结果的缓冲区
 @param err 返回错误
 @return output 中存储的字节数
 */
-(NSInteger)doFinal:(NSData*)input inputoffset:(NSInteger)inputoffset inputLen:(NSInteger)inputLen output:(NSData**)output err:(NSError**)err;


/**
 按单部分操作加密或解密数据，或者结束一个多部分操作。数据将被加密或解密（具体取决于此 Cipher 的初始化方式）

 @param input 输入缓冲区
 @param inputoffset 输入起始处的偏移量
 @param inputLen 输入长度
 @param output 保存结果的缓冲区
 @param outputoffset output 中存储结果处的偏移量
 @param err 返回错误
 @return output 中存储的字节数
 */
-(NSInteger)doFinal:(NSData*)input inputoffset:(NSInteger)inputoffset inputLen:(NSInteger)inputLen output:(NSData**)output outputoffset:(NSInteger)outputoffset err:(NSError**)err;


/**
 按单部分操作加密或解密数据，或者结束一个多部分操作。数据将被加密或解密（具体取决于此 Cipher 的初始化方式）

 @param input 输入 NSData
 @param output 输出 NSData
 @param err 返回错误
 @return output 中存储的字节数
 */
-(NSInteger)doFinal:(NSData*)input output:(NSData**)output err:(NSError**)err;


/**
 返回此 Cipher 对象的算法名称

 @return 此 Cipher 对象的算法名称
 */
-(NSString*)getAlgorithm;


/**
 返回块的大小（以字节为单位）

 @return 块的大小（以字节为单位）；如果底层算法不是 Cipher 块，则返回 0
 */
-(NSInteger)getBlockSize;



/**
 返回此 Cipher 使用的豁免 (exemption) 机制对象

 @return 此 Cipher 使用的豁免机制对象，如果此 Cipher 不使用任何豁免机制，则返回 null
 */
// 暂不实现
-(ExemptionMechanism*)getExemptionMechanism;



/**
 返回实现指定转换的 Cipher 对象

 @param transformation 转换的名称，例如 DES/CBC/PKCS5Padding
 @param err 返回错误
 @return 实现所请求转换的 Cipher
 */
+(Cipher*)getInstance:(NSString*)transformation err:(NSError**)err;


/**
 返回实现指定转换的 Cipher 对象

 @param transformation 转换的名称，例如 DES/CBC/PKCS5Padding
 @param provider  提供者
 @param err 返回错误
 @return 实现所请求转换的 Cipher
 */
+(Cipher*)getInstance:(NSString*)transformation provider:(Provider*)provider err:(NSError**)err;


/**
 返回实现指定转换的 Cipher 对象

 @param transformation 转换的名称，例如 DES/CBC/PKCS5Padding
 @param provider 提供者的名称
 @param err 返回错误
 @return 实现所请求转换的 Cipher
 */
+(Cipher*)getInstanceWithProvider:(NSString*)transformation provider:(NSString*)provider err:(NSError**)err;


/**
 返回新缓冲区中的初始化向量 (IV)

 @return 新缓冲区中的初始化向量；如果底层算法不使用 IV，或者 IV 尚未设置，则返回 null
 */
-(NSData*)getIV;


/**
 根据所安装的 JCE 仲裁策略文件，返回指定转换的最大密钥长度。

 @param transformation Cipher 转换
 @param err 返回错误
 @return 最大密钥长度（以位为单位） 或 Integer.MAX_VALUE
 */
-(NSInteger)getMaxAllowedKeyLength:(NSString*)transformation err:(NSError**)err;


/**
 根据仲裁策略文件，返回包含最大 Cipher 参数值的 AlgorithmParameterSpec 对象。如果安装了 JCE 无限制强度仲裁策略文件，
 或者策略文件中对用于指定转换的参数没有最大限制，则返回 null

 @param transformation  Cipher 转换
 @param err 返回错误
 @return 保存最大值的 AlgorithmParameterSpec，或者返回 null
 */
-(id<AlgorithmParameterSpec>)getMaxAllowedParameterSpec:(NSString*)transformation err:(NSError**)err;



/**
 根据给定的输入长度 inputLen（以字节为单位），返回保存下一个 update 或 doFinal 操作结果所需的输出缓冲区长度（以字节为单位）

 @param inputLen 输入长度（以字节为单位）
 @return 所需的输出缓冲区大小（以字节为单位）
 */
-(NSInteger)getOutputSize:(NSInteger)inputLen err:(NSError**)err;


/**
 返回此 Cipher 使用的参数

 @return return 此 Cipher 使用的参数；如果此 Cipher 不使用任何参数，则返回 null
 */
-(AlgorithmParameters*)getParameters;


/**
 返回此 Cipher 对象的提供者

 @return 此 Cipher 对象的提供者
 */
-(Provider*)getProvider;


/**
 用取自给定证书的公钥初始化此 Cipher

 @param opmode 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param certificate 证书
 @param err 返回错误
 */
-(void)initializeWithMode:(NSInteger)opmode certificate:(Certificate*)certificate err:(NSError**)err;



/**
 用取自给定证书的公钥和随机源初始化此 Cipher

 @param opmode 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param certificate 证书
 @param random 随机源
 @param err 返回错误
 */
-(void)initializeWithMode:(NSInteger)opmode certificate:(Certificate*)certificate random:(SecureRandom*)random err:(NSError**)err;


/**
 用密钥初始化此 Cipher

 @param opmode 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 密钥
 @param err 返回错误
 */
-(void)initializeWithMode:(NSInteger)opmode key:(id<Key>)key err:(NSError**)err;


/**
 用密钥和一组算法参数初始化此 Cipher

 @param opmode 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 加密密钥
 @param params 算法参数
 @param err 返回错误
 */
-(void)initializeWithMode:(NSInteger)opmode key:(id<Key>)key params:(AlgorithmParameters*)params  err:(NSError**)err;


/**
 用密钥和一组算法参数初始化此 Cipher

 @param opmode 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 加密密钥
 @param params 算法参数
 @param err 返回错误
 */
-(void)initializeWithParam:(NSInteger)opmode key:(id<Key>)key params:(id<AlgorithmParameterSpec>)params  err:(NSError**)err;


/**
 用一个密钥、一组算法参数和一个随机源初始化此 Cipher

 @param opmode 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 加密密钥
 @param params 算法参数
 @param random 随机源
 @param err 返回错误
 */
-(void)initializeWithParam:(NSInteger)opmode key:(id<Key>)key params:(id<AlgorithmParameterSpec>)params  random:(SecureRandom*)random err:(NSError**)err;


/**
 用一个密钥、一组算法参数和一个随机源初始化此 Cipher

 @param opmode 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 加密密钥
 @param params 算法参数
 @param random 随机源
 @param err 返回错误
 */
-(void)initializeWithMode:(NSInteger)opmode key:(id<Key>)key params:(AlgorithmParameters*)params  random:(SecureRandom*)random err:(NSError**)err;


/**
 用密钥和随机源初始化此 Cipher

 @param opmode  此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 加密密钥
 @param random 随机源
 @param err 返回错误
 */
-(void)initializeWithMode:(NSInteger)opmode key:(id<Key>)key random:(SecureRandom*)random err:(NSError**)err;


/**
 解包一个以前包装的密钥

 @param wrappedKey 要解包的密钥
 @param wrappedKeyAlgorithm 与此包装密钥关联的算法
 @param wrappedKeyType 已包装密钥的类型。此类型必须为 SECRET_KEY、PRIVATE_KEY 或 PUBLIC_KEY 之一
 @return 返回错误
 */
//暂不实现
-(id<Key>)unwrap:(NSData*)wrappedKey wrappedKeyAlgorithm:(NSString*)wrappedKeyAlgorithm wrappedKeyType:(NSInteger)wrappedKeyType err:(NSError**)err;


/**
 继续多部分加密或解密操作（具体取决于此 Cipher 的初始化方式），以处理其他数据部分

 @param input 输入缓冲区
 @return 包含结果的新缓冲区；如果底层 Cipher 为 Cipher 块并且输入数据太短而无法形成新的块，则返回 null
 */
-(NSData*)update:(NSData*)input err:(NSError**)err;


/**
 继续多部分加密或解密操作（具体取决于此 Cipher 的初始化方式），以处理其他数据部分

 @param input 输入缓冲区
 @param inputOffset 输入起始处的偏移量
 @param inputLen 输入长度
 @return 返回错误
 */
-(NSData*)update:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen err:(NSError**)err;


/**
 继续多部分加密或解密操作（具体取决于此 Cipher 的初始化方式），以处理其他数据部分

 @param input 输入缓冲区
 @param inputOffset 输入起始处的偏移量
 @param inputLen 输入长度
 @param output 保存结果的缓冲区
 @return output 中存储的字节数
 */
-(NSInteger)update:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData**)output err:(NSError**)err;


/**
 继续多部分加密或解密操作（具体取决于此 Cipher 的初始化方式），以处理其他数据部分

 @param input 输入缓冲区
 @param inputOffset 输入起始处的偏移量
 @param inputLen 输入长度
 @param output 保存结果的缓冲区
 @param outputOffset 存储结果处的偏移量
 @param err 返回错误
 @return 存储的字节数
 */
-(NSInteger)update:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData**)output outputOffset:(NSInteger)outputOffset err:(NSError**)err;


/**
 继续多部分加密或解密操作（具体取决于此 Cipher 的初始化方式），以处理其他数据部分

 @param input 输入 NSData
 @param output 输出 NSData
 @return output 中存储的字节数
 */
-(NSInteger)update:(NSData*)input output:(NSData**)output err:(NSError**)err;


/**
 包装密钥

 @param key 要包装的密钥
 @param err 返回错误
 @return 已包装的密钥
 */
// 暂不实现
-(NSData*)wrap:(id<Key>)key err:(NSError**)err;

@end
