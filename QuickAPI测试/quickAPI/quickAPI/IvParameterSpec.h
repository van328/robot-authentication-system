//
//  IvParameterSpec.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/2.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AlgorithmParameterSpec.h"
@interface IvParameterSpec : NSObject<AlgorithmParameterSpec>
/**
 获取到iv参数实例

 @param iv 初始化向量
 @return 实例
 */
-(instancetype)initWithIV:(NSData *)iv;
/**
 获取到iv参数实例

 @param iv 初始化向量
 @param offset iv开始截取的偏移量
 @param len iv截取的长度
 @return 实例
 */
-(instancetype)initWithIV:(NSData *)iv offset:(int)offset length:(int)len;
/**
 获取初始化向量

 @return 初始化向量
 */
-(NSData *)getIv;
@end
