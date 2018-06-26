//
//  SignatureSpi.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/12.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PrivateKey.h"
#import "PublicKey.h"
#import "SecureRandom.h"
#import "AlgorithmParameterSpec.h"
#import "AlgorithmParameters.h"
#import <MultiKey/MultiKey.h>
@protocol SignatureSpi <NSObject>

/**
 已过时。
 获取指定算法参数的值。此方法提供了一种通用机制，通过它能够获取此对象的各种参数。
 参数可以是算法的任何可设置参数，如参数大小、签名生成的随机源位（如果适当），
 或者表示是否执行具体但可选的计算。每个参数都需要统一的、特定于算法的命名方案，
 但此时尚未指定这种方案

 @param param 参数的字符串名称
 @param err 返回错误
 @return 表示参数值的对象，如果没有，则返回 null
 */
//-(Object)engineGetParameter:(NSString*)param err:(NSError **)err;


/**
 此方法将由提供者重写，以返回与此签名引擎配合使用的参数，如果此签名引擎未使用任何参数，则返回 null

 @return 与此签名引擎一块使用的参数，如果此签名引擎未使用任何参数，则返回 null
 */
-(AlgorithmParameters*)engineGetParameters:(NSError **)err;


/**
 通过用于签名操作的指定私钥初始化此签名对象

 @param privatekey 将生成其签名的标识的私钥
 @param err 返回错误
 */
-(void)engineInitSign:(id<PrivateKey>)privatekey err:(NSError **)err;


/**
 通过用于签名操作的指定私钥和随机源初始化此签名对象

 @param privateKey 将生成其签名的标识的私钥
 @param random 随机源
 @param err 返回错误
 */
-(void)engineInitSign:(id<PrivateKey>)privateKey random:(SecureRandom*)random err:(NSError **)err;


/**
 通过用于验证操作的指定公钥初始化此签名对象

 @param publicKey 其签名将被验证的标识的公钥
 @param err 返回错误
 */
-(void)engineInitVerify:(id<PublicKey>)publicKey err:(NSError **)err;


/**
 此方法将由提供者重写，以便使用指定的参数设置初始化此签名引擎

 @param params 参数
 @param err 返回错误
 */
-(void)engineSetParameter:(id<AlgorithmParameterSpec>)params err:(NSError **)err;


/**
 已过时。
 由 engineSetParameter 取代

 @param param  参数的字符串标示符
 @param value 参数值
 */
-(void)engineSetParameter:(NSString*)param value:(NSObject*)value;


/**
 返回迄今为止所有更新的数据的签名字节。签名的格式取决于底层签名方案

 @param err 返回错误
 @return 签名操作结果的签名字节
 */
-(NSData*)engineSign:(NSError **)err;


/**
 完成此签名操作，并从 offset 开始将得到的签名字节保存在提供的缓冲区 outbuf 中。签名的格式取决于基本签名方案

 @param outbuf 输出签名结果的缓冲区
 @param offset 到存储签名的 outbuf 的偏移量
 @param len outbuf 中分配给签名的字节数
 @param err 返回错误
 @return 放入 outbuf 中的字节数
 */
-(NSInteger)engineSign:(NSData*)outbuf offset:(NSInteger)offset len:(NSInteger)len err:(NSError **)err;


/**
 使用指定的字节更新要签名或验证的数据

 @param b 用于更新的字节
 @param err 返回错误
 */
-(void)engineUpdate:(Byte)b err:(NSError **)err;


/**
 使用指定的 byte 数组，从指定的偏移量开始更新要签名或验证的数据

 @param b 数组
 @param off 数组开始处的偏移量
 @param len 要使用的字节数（从偏移量开始处计算）
 @param err 返回错误
 */
-(void)engineUpdate:(NSData*)b off:(NSInteger)off len:(NSInteger)len err:(NSError **)err;


/**
 使用指定的 ByteBuffer 更新要签名或验证的数据。处理从 data.position() 处开始的 data.remaining() 字节。
 返回时，缓冲区的位置将等于其限制；其限制并未改变

 @param input NSData
 */
-(void)engineUpdate:(NSData*)input;


/**
 验证传入的签名

 @param sigBytes 要验证的签名字节
 @param err 返回错误
 @return 如果签名得到验证，则返回 true，否则将返回 false
 */
-(BOOL)engineVerify:(NSData*)sigBytes err:(NSError **)err;


/**
 在指定的 NSData 数组中，从指定的偏移量处开始，验证传入的签名

 @param sigBytes 要验证的签名字节
 @param offset 数组中起始处的偏移量
 @param len 要使用的字节数（从偏移量起始处计算）
 @param err 返回错误
 @return 如果签名得到验证，则返回 true，否则将返回 false
 */
-(BOOL)engineVerify:(NSData*)sigBytes offset:(NSInteger)offset len:(NSInteger)len err:(NSError **)err;
@end
