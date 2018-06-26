//
//  CipherInterface.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/6.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
@protocol Key;
@class AlgorithmParameters;
@protocol AlgorithmParameterSpec;
@class SecureRandom;
@protocol CipherInterface <NSObject>

/**
 按单部分操作加密或解密数据，或者结束一个多部分操作。数据被加密还是解密取决于此 cipher 的初始化方式。
 处理 input 缓冲区中从 inputOffset 开始（包含）的前 inputLen 个字节以及可能在上一次 update 操作过程中已缓存的任何输入字节，
 其中应用了填充（如果需要）。结果存储在新缓冲区中。结束时，此方法将把此 cipher 对象重置为上一次调用 engineInit 初始化得到的状态。
 即重置该对象，可供加密或解密（取决于调用 engineInit 时指定的操作模式）更多的数据。

 @param input 输入缓冲区
 @param inputOffset 输入开始位置的偏移量
 @param inputLen 输入长度
 @param err 返回错误
 @return 存储结果的新缓冲区
 */
-(NSData*)engineDoFinal:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen err:(NSError**)err;


/**
 按单部分操作加密或解密数据，或者结束一个多部分操作。数据被加密还是解密取决于此 cipher 的初始化方式.
 处理 input 缓冲区中从 inputOffset 开始（包含）的前 inputLen 个字节以及可能在上一次 update
 操作过程中已缓存的任何输入字节，其中应用了填充（如果需要）。结果存储在 output 缓冲区中从 outputOffset（包含）开始的位置。

 @param input 输入缓冲区
 @param inputOffset 输入开始位置的偏移量
 @param inputLen 输入长度
 @param output 保存结果的缓冲区
 @param outputOffset 存储结果的位置的偏移量
 @return output 中存储的字节数
 */
-(NSInteger)engineDoFinal:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData**)output outputOffset:(NSInteger)outputOffset err:(NSError**)err;


/**
 按单部分操作加密或解密数据，或者结束一个多部分操作。数据被加密还是解密取决于此 cipher 的初始化方式。
 处理从 input.position() 开始的所有 input.remaining() 字节。结果存储在输出缓冲区中。返回时，
 输入缓冲区的位置将等于其限制；其限制并未改变。输出缓冲区的位置将前移 n，其中 n 为此方法返回的值；
 输出缓冲区的限制并未改变。

 @param input 输入 NSData
 @param output 输出 NSData
 @param err 返回错误
 @return output 中存储的字节数
 */
-(NSInteger)engineDoFinal:(NSData*)input  output:(NSData**)output err:(NSError**)err;


/**
 返回块的大小（以字节为单位）

 @return 返回块的大小（以字节为单位）
 */
-(NSInteger)engineGetBlockSize;


/**
 返回新缓冲区中的初始化向量 (IV)

 @return 返回新缓冲区中的初始化向量 (IV)
 */
-(NSData*)engineGetIV;


/**
 返回给定密钥对象的密钥大小，以位为单位。

 @param key 密钥对象
 @param err 返回错误
 @return 给定密钥对象的密钥大小
 */
-(NSInteger)engineGetKeySize:(id<Key>)key err:(NSError**)err;


/**
 在给定了输入长度 inputLen（以字节为单位）的情况下，返回用于保存下一个 update 或 doFinal 操作结果所需的输出缓冲区长度的字节数。
 此调用还考虑到来自上一个 update 调用的任何未处理（已缓存）的数据和填充。

 @param inputLen 输入长度（以字节为单位）
 @return 所需的输出缓冲区大小（以字节为单位）
 */
-(NSInteger)engineGetOutputSize:(NSInteger)inputLen;


/**
 返回此 cipher 使用的参数
 返回的参数可能与初始化此 cipher 所使用的参数相同；如果此 cipher 要求使用算法参数但却未使用任何参数进行初始化，
 则返回的参数可能会包含由默认值和底层 cipher 实现所使用的随机参数值的组合。

 @return 此 cipher 使用的参数，如果此 cipher 不使用任何参数，则返回 null
 */
-(id<AlgorithmParameterSpec>)engineGetParameters;


/**
 用一个密钥、一组算法参数和一个随机源初始化此 cipher

 @param opmode 此 cipher 的操作模式（其为如下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 加密密钥
 @param params 算法参数
 @param random  随机源
 */
-(void)engineInit:(NSInteger)opmode key:(id<Key>)key  params:(id<AlgorithmParameterSpec>)params random:(SecureRandom*)random err:(NSError**)err;


/**
 用一个密钥、一组算法参数和一个随机源初始化此 cipher。

 @param opmode 此 cipher 的操作模式（其为如下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 加密密钥
 @param params 算法参数
 @param random  随机源
 @param err 返回错误
 */
-(void)engineInitWithParam:(NSInteger)opmode key:(id<Key>)key params:(AlgorithmParameters*)params random:(SecureRandom*)random err:(NSError**)err;


/**
 用密钥和随机源初始化此 cipher

 @param opmode 此 cipher 的操作模式（其为如下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）
 @param key 加密密钥
 @param random 随机源
 @param err 返回错误
 */
-(void)engineInit:(NSInteger)opmode key:(id<Key>)key  random:(SecureRandom*)random err:(NSError**)err;


/**
 设置此 cipher 的模式

 @param mode cipher 模式
 */
-(void)engineSetMode:(NSString*)mode err:(NSError**)err;


/**
 设置此 cipher 的填充机制

 @param padding 填充机制
 */
-(void)engineSetPadding:(NSString*)padding err:(NSError**)err;



/**
 打开一个以前包装的密钥

 @param wrappedKey 要打开的密钥
 @param wrappedKeyAlgorithm 与此包装密钥关联的算法
 @param wrappedKeyType 已包装密钥的类型。此类型为 SECRET_KEY、PRIVATE_KEY 或 PUBLIC_KEY 之一
 @param err 返回错误
 @return 打开的密钥
 */
-(id<Key>)engineUnwrap:(NSData*)wrappedKey wrappedKeyAlgorithm:(NSString*)wrappedKeyAlgorithm wrappedKeyType:(NSInteger)wrappedKeyType err:(NSError**)err;


/**
 继续多部分加密或解密操作（取决于此 cipher 的初始化方式），以处理其他数据部分。
 处理 input 缓冲区中从 inputOffset 开始（包含）的前 inputLen 个字节，并将结果存储在新的缓冲区中

 @param input 输入缓冲区
 @param inputOffset 输入开始位置的偏移量
 @param inputLen 输入长度
 @return 包含结果的新缓冲区，如果底层 cipher 为块 cipher 并且输入数据太短而无法形成新的块时，则返回 null
 */
-(NSData*)engineUpdate:(NSData*)input inputOffset:(NSInteger)inputOffset  inputLen:(NSInteger)inputLen err:(NSError**)err;


/**
 继续多部分加密或解密操作（取决于此 cipher 的初始化方式），以处理其他数据部分。

 @param input 输入缓冲区
 @param inputOffset 输入开始位置的偏移量
 @param inputLen 输入长度
 @param output 保存结果的缓冲区
 @param outputOffset 存储结果的位置的偏移量
 @param err 返回错误
 @return 存储的字节数
 */
-(NSInteger)engineUpdate:(NSData*)input inputOffset:(NSInteger)inputOffset inputLen:(NSInteger)inputLen output:(NSData**)output outputOffset:(NSInteger)outputOffset err:(NSError**)err;


/**
 继续多部分加密或解密操作（取决于此 cipher 的初始化方式），以处理其他数据部分。

 @param input 输入 NSData
 @param output 输出 NSData
 @return output 中存储的字节数
 */
-(NSInteger)engineUpdate:(NSData*)input output:(NSData**)output err:(NSError *__autoreleasing *)err;


/**
 将密钥包装。

 @param key 要包装的密钥
 @param err 返回错误
 @return 已包装的密钥
 */
-(NSData*)engineWrap:(id<Key>)key err:(NSError**)err;
@end
