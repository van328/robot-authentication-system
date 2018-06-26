//
//  macInterface.h
//  quickAPI
//
//  Created by SecureChip on 2018/1/31.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
@protocol Key;
@protocol AlgorithmParameterSpec;
@protocol macInterface <NSObject>

/**
 用给定的（秘密）密钥和算法参数初始化 MAC

 @param key 秘密）密钥
 @param algorithmparameterSpec 算法参数
 @param err 返回错误
 */
-(void)engineInit:(id<Key>)key algorithmparameterSpec:(id<AlgorithmParameterSpec>)algorithmparameterSpec err:(NSError**)err;



/**
 处理给定的字节

 @param input 要处理的输入字节
 */
-(NSInteger)engineUpdate:(Byte)input;


/**
 从 offset 开始处（包含），处理 input 中的前len 个字节

 @param input ：输入缓冲区
 @param offset ：input 中输入开始处的偏移量
 @param len ：要处理的字节数
 */
-(NSInteger)engineUpdate:(NSData*)input offset:(NSInteger)offset len:(NSInteger)len;


/**
 完成 MAC 计算并且重新设置 MAC 以便进一步使用，维护 MAC 初始化所用的秘密密钥

 @param err 返回错误
 @return MAC 的结果
 */
-(NSData*)engineDoFinal:(NSError**)err;


/**
 为了进一步使用而重新设置 MAC，维护 MAC 初始化所用的秘密密钥

 @param err 返回错误
 */
-(void)engineReset:(NSError**)err;


/**
 返回以字节为单位的 MAC 的长度

 @return 以字节为单位的 MAC 长度
 */
-(NSInteger)engineGetMacLength;
@end
