//
//  SecretKeySpec.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/2.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Key.h"
@interface SecretKeySpec : NSObject<Key>
/**
 密钥实例

 @param key 密钥字节数组
 @param alg 算法标识
 @return 密钥实例
 */
-(instancetype)initWithKey:(NSData *)key algorithm:(NSString *)alg;
/**
 密钥实例

 @param key 密钥字节数组
 @param offset 密钥截取偏移量
 @param len 密钥截取长度
 @param alg 算法标识
 @return 密钥实例
 */
-(instancetype)initWithKey:(NSData *)key offset:(int)offset length:(int)len algorithm:(NSString *)alg;
@end
