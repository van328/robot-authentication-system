//
//  Key.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/2.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol Key <NSObject>
/**
 返回此密钥的标准算法名称

 @return 返回此密钥的标准算法名称
 */
-(NSString *)getAlgorithm;
/**
 返回此密钥的基本编码格式，如果此密钥不支持编码，则返回 nil。

 @return 返回此密钥的基本编码格式，如果此密钥不支持编码，则返回 nil。
 */
-(NSString *)getFormat;
/**
 返回基本编码格式的密钥，如果此密钥不支持编码，则返回 nil。

 @return 返回基本编码格式的密钥，如果此密钥不支持编码，则返回 nil。
 */
-(NSData *)getEncoded;
@end
