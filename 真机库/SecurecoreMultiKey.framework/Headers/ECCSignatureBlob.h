//
//  EccSignatureBloc.h
//  Dcs
//
//  Created by 赵利 on 16/10/27.
//  Copyright © 2016年 cn.dacas. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECCSignatureBlob : NSObject
@property(nonatomic,strong,readonly)NSData *s;
@property(nonatomic,strong,readonly)NSData *r;

/**
 判断当前对象是否合法

 @return yes合法，no不合法
 */
-(BOOL) isValid;
/**
 设置r

 @param r r
 */
-(void)setR:(NSData *)r;
/**
 设置s

 @param s s
 */
-(void)setS:(NSData *)s;
/**
 将当前对象转为字符串
 
 @return 对象的字符串输出
 */
-(NSString*)toString;
/**
 将签名对象转换为二进制串

 @return 签名结果转换为二进制串
 */
-(NSData *)toByteArray;
/**
 使用二进制串为签名结果对象属性复制

 @param signedData 签名二进制串
 @return YES表示赋值成功 NO表示赋值失败
 */
-(BOOL) readFromByteArray:(NSData *)signedData;
@end
