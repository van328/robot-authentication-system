//
//  Signature.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/28.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PublicKey.h"
#import "PrivateKey.h"
#import "SecureRandom.h"
#import "AlgorithmParameterSpec.h"
#import "AlgorithmParameters.h"
@interface Signature : NSObject
+(Signature*)getInstanceWithProvider:(NSString*)transformation provider:(NSString*)provider err:(NSError**)err;

/**
 初始化验签对象，如果改方法被使用不同的参数进行第二次调用，那么忽略本次调用结果

 @param publicKey 验签需要的公钥
 @param err 返回错误
 */
-(void)initVerify:(id<PublicKey>) publicKey err:(NSError**)err;

/**
 初始化签名对象，如果改方法被使用不同的参数进行第二次调用，那么忽略本次调用结果

 @param privateKey 签名需要的私钥
 @param err 返回错误
 */
-(void)initSign:(id<PrivateKey>) privateKey err:(NSError**)err;


/**
 初始化签名对象，如果改方法被使用不同的参数进行第二次调用，那么忽略本次调用结果

 @param privateKey 签名需要的私钥
 @param random 签名的随机数源
 @param err 返回错误
 */
-(void)initSign:(id<PrivateKey>)privateKey random:(SecureRandom*)random err:(NSError**)err;


/**
 返回签名结果

 @param err 返回错误
 @return 返回签名结果
 */
-(NSData*)sign:(NSError**)err;
/**
 结束签名操作，返回签名结果
 
 @param outbuf 保存签名结果
 @param offset 签名结果在outbuf中的偏移量
 @param len outbuf中为签名结果分配的字节数
 @param err 返回错误
 @return 保存到outbuf中的签名结果长度
 */
-(NSInteger)sign:(NSData*)outbuf offset:(NSInteger)offset len:(NSInteger)len err:(NSError**)err;

/**
 对签名结果进行认证

 @param signature 签名信息
 @param err 返回错误
 @return 返回签名认证结果
 */
-(BOOL)verify:(NSData*)signature err:(NSError**)err;

/**
 对数组中的签名信息进行认证

 @param signature 需要认证的签名信息
 @param offset 签名信息在数组中的偏移量
 @param length 签名信息字节长度
 @param err 返回错误
 @return 返回认证结果
 */
-(BOOL)verify:(NSData*)signature offset:(NSInteger)offset length:(NSInteger)length err:(NSError**)err;

/**
 更新签名或者验签字节

 @param b 用于更新的字节
 @param err 返回错误
 */
-(void)updata:(Byte)b err:(NSError**)err;

/**
 更新签名或者验签字节

 @param data 用于更新的数组
 @param err 返回错误
 */
-(void)updataWithData:(NSData*)data err:(NSError**)err;

/**
 更新签名或者验签数据，使用指定的数组字节

 @param data 签名或者验签数据的数组
 @param off 数据在数组偏移量
 @param len 数据长度
 @param err 返回错误
 */
-(void)updata:(NSData*)data off:(NSInteger)off len:(NSInteger)len err:(NSError**)err;

/**
 返回签名对象算法名称

 @return 签名对象的算法名称
 */
-(NSString*)getAlgorithm;

/**
 为算法参数设置特定值

 @param param 算法参数
 @param value 设置的参数值
 @param err 返回错误
 */
-(void)setParameter:(NSString*)param value:(NSObject*)value err:(NSError**)err;

/**
 使用参数集初始化签名引擎

 @param params 参数
 @param err 返回错误
 */
-(void)setParameter:(id<AlgorithmParameterSpec>)params err:(NSError**)err;

/**
 返回签名对象参数

 @return 签名对象的参数值
 */
-(AlgorithmParameters*)getParameters:(NSError**)err;


@end
