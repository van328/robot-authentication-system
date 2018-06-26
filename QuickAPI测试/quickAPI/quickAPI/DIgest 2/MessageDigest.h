//
//  MessageDigest.h
//  quickAPI
//
//  Created by SecureChip on 2018/1/30.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "DigestInterface.h"
@interface MessageDigest : NSObject<DigestInterface>
/**
 返回实现指定摘要算法的 MessageDigest 对象
 返回封装 MessageDigestSpi 实现的新 MessageDigest 对象，该实现取自指定提供者。指定提供者必须在安全提供者列表中注册
 
 @param alg 所请求算法的名称
 @param provider 提供者的名称
 @return 实现指定算法的 MessageDigest 对象
 */
+(instancetype)getInstance:(NSString*)alg provider:(NSString*)provider;

/**
 初始化方法
 
 @param alg 算法标志
 @return MessageDigest 实例
 */
-(instancetype)initWithAlg:(NSString *)alg;

/**
 返回以字节为单位的摘要长度，如果提供者不支持此操作并且实现是不可复制的，则返回 0
 
 @return 以字节为单位的摘要长度，如果提供者不支持此操作并且实现是不可复制的，则返回 0
 */
-(NSInteger)getDigestLength;
/**
 返回标识算法的独立于实现细节的字符串
 */
-(NSString*)getAlgorithm;
/**
 重置摘要以供再次使用
 */
-(void)reset:(NSError **)err;
/**
 使用指定的字节更新摘要
 
 @param input 用于更新摘要的字节
 */
-(void)update:(Byte)input error:(NSError **)err;;
/**
 使用指定的 NSData 数组更新摘要
 
 @param input  NSData数组
 */
-(void)updateWithData:(NSData*)input error:(NSError **)err;;
/**
 使用指定的 NSData 数组，从指定的偏移量开始更新摘要
 
 @param input 数组
 @param offset 数组中的偏移量，操作从此处开始
 @param len 要使用的字节数，始于 offset
 */
-(void)update:(NSData*)input offset:(NSInteger)offset len:(NSInteger)len error:(NSError **)err;;
/**
 通过执行诸如填充之类的最终操作完成哈希计算。在调用此方法之后，摘要被重置
 
 @return 存放哈希值结果的 NSData 数组
 */
-(NSData*)Digest:(NSError **)err;;
/**
 使用指定的 byte 数组对摘要进行最后更新，然后完成摘要计算
 
 @param input 在完成摘要计算前要更新的输入
 @return 存放哈希值结果的 NSData 数组
 */
-(NSData*)Digest:(NSData*)input error:(NSError **)err;
/**
 通过执行诸如填充之类的最终操作完成哈希计算。在调用此方法之后，摘要被重置
 
 @param buf 存放计算摘要的输出缓冲区
 @param offset 输出缓冲区中的偏移量，从此处开始存储摘要
 @param len 在 buf 中分配给摘要的字节数
 @param err 返回错误
 @return 放到 buf 中的字节数
 */
-(NSInteger)Digest:(NSData**)buf offset:(NSInteger)offset len:(NSInteger)len error:(NSError **)err;


@end
