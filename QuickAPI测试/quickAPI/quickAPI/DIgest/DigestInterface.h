//
//  DigestInterface.h
//  quickAPI
//
//  Created by SecureChip on 2018/1/30.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol DigestInterface <NSObject>


/** 使用指定的字节更新摘要

 @param input 更新所使用的字节
 */
-(NSInteger)engineUpdate:(Byte)input;

/**
 使用指定的 input 更新摘要
 
 @param input :input
 */
-(NSInteger)engineUpdateWithData:(NSData*)input;

/**
 使用指定的 byte 数组，在指定的偏移量处开始更新摘要

 @param input 用来更新的 byte 数组
 @param offset 数组中的偏移量，操作从此处开始
 @param len 要使用的字节数
 */
-(NSInteger) engineUpdate:(NSData*)input offset:(NSInteger)offset len:(NSInteger)len;


/**
 通过执行诸如填充等之类的最终操作完成哈希计算。一旦 engineDigest 被调用，引擎应该被重置.重置由引擎实现者负责

 @param err 返回错误
 @return 存放哈希值结果的数组
 */
-(NSData*)engineDigest:(NSError**)err;

/**
 通过执行诸如填充等之类的最终操作完成哈希计算。一旦 engineDigest 被调用，引擎应该被重置.重置由引擎实现者负责

 @param buf 存储摘要的输出缓冲区
 @param offset 输出缓冲区中的偏移量，操作从此处开始
 @param len 在 buf 中分配给摘要的字节数。
 @return 存储在输出缓冲区中的摘要长度
 */
-(NSInteger)engineDigest:(NSData**)buf offset:(NSInteger)offset len:(NSInteger)len err:(NSError**)err;

/**
 为进一步使用重置摘要
 
 @param err 返回错误
 */
-(void) engineReset:(NSError**)err;

/**
 返回以字节为单位的摘要长度

 @return 以字节为单位的摘要长度
 */
-(NSInteger)engineGetDigestLength;


@end
