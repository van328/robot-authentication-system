//
//  MAC.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/1.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
@protocol macInterface;
@protocol Key;
@protocol AlgorithmParameterSpec;
@interface MAC : NSObject
/**
 初始化mac对象

 @param mac 实现了macinterface的对象
 @param alg 算法标志
 @return mac对象
 */
-(instancetype)initWithMac:(id<macInterface>)mac algorithm:(NSString *)alg;
/**
 完成MAC操作
 
 对此方法的调用将此 Mac 对象重置为上一次调用 init(Key) 或 init(Key, AlgorithmParameterSpec) 初始化的状态。
 也就是说，该对象被重置，并可通过重新调用 updatdoFinal（如果需要）从同一个密钥生成另一个 MAC。（若要用不同的密钥
 重用此 Mac 对象，则必须通过调用 init(Key) 或 init(Key, AlgorithmParameterSpec) 对其重新初始化）。
 
 @param err 返回异常错误
 @return MAC 的结果
 */
-(NSData*)doFinal:(NSError**)err;


/**
 处理给定的NSData数组并且完成MAC操作
 
 对此方法的调用将此 Mac 对象重置为上一次调用 init(Key) 或 init(Key, AlgorithmParameterSpec) 初始化的状态。
 也就是说，该对象被重置，并可通过重新调用 update 和 doFinal（如果需要）从同一个密钥生成另一个 MAC。（若要用不同
 的密钥重用此 Mac 对象，则必须通过调用 init(Key) 或 init(Key, AlgorithmParameterSpec) 对其重新初始化）。
 
 @param input 字节中的数据
 @param err 返回异常错误
 @return MAC 的结果
 */
-(NSData*)doFinal:(NSData*)input err:(NSError**)err;


/**
 完成 MAC 操作。
对此方法的调用将此 Mac 对象重置为上一次调用 init(Key) 或 init(Key, AlgorithmParameterSpec) 初始化的状态。
 也就是说，该对象被重置，并可通过重新调用 update 和 doFinal（如果需要）从同一个密钥生成另一个 MAC。（若要用不同
 的密钥重用此 Mac 对象，则必须通过调用 init(Key) 或 init(Key, AlgorithmParameterSpec) 对其重新初始化）。
 
 @param output :存储 MAC 结果的缓冲区
 @param outoffset :output 中存储 MAC 处的偏移量
 */
-(void)doFinal:(NSData**)output outoffset:(NSInteger)outoffset err:(NSError**)err;


/**
 返回此 Mac 对象的算法名称.
 @return Mac 对象的算法名称
 */
-(NSString*)getAlgorithm;




/**
 返回实现指定 MAC 算法的 Mac 对象
 返回一个封装 MacSpi 实现的新 Mac 对象，该实现自指定的提供者。指定提供者必须在安全提供者列表中注册。

 @param algorithm 所请求 MAC 算法的标准名称
 @param provider 提供者的名称
 @return 新的 Mac 对象
 */
+(MAC*)getInstance:(NSString*)algorithm provider:(NSString*)provider;


/**
 返回 MAC 的长度，以字节为单位

 @return MAC 长度，以字节为单位
 */
-(NSInteger)getMacLength;


/**
 用给定的密钥初始化此 Mac 对象

 @param key 密钥
 @param err 返回异常错误
 */
-(void)init:(id<Key>)key err:(NSError**)err;

/**
 用给定的密钥和算法参数初始化此 Mac 对象

 @param key 密钥
 @param params 算法参数
 @param err 返回异常错误
 */
-(void)init:(id<Key>)key  params:(id<AlgorithmParameterSpec>)params err:(NSError**)err;


/**
 重置此 Mac 对象
 对此方法的调用将此 Mac 对象重置为上一次调用 init(Key) 或 init(Key, AlgorithmParameterSpec) 初始化的状态。
 也就是说，该对象被重置，并可通过重新调用 update 和 doFinal（如果需要）从同一个密钥生成另一个 MAC。（若要用不同的
 密钥重用此 Mac 对象，则必须通过调用 init(Key) 或 init(Key, AlgorithmParameterSpec) 对其重新初始化）
 */
-(void)reset:(NSError **)err;


/**
 处理给定的字节

 @param input 要处理的输入字节
 @param err 返回异常错误
 */
-(void)update:(Byte)input err:(NSError**)err;

/**
 处理给定的 byte 数组

 @param input 要处理的 byte 数组
 @param err 返回异常错误
 */
-(void)updateWithData:(NSData*)input err:(NSError**)err;

/**
 从 offset（包含）开始，处理 input 中的前 len 个字节

 @param input 输入缓冲区
 @param err 返回异常错误
 */
-(void)update:(NSData*)input offset:(NSInteger)offset len:(NSInteger)len err:(NSError**)err;

@end
