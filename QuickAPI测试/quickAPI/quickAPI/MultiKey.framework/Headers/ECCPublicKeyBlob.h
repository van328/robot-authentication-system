//
//  EccPublicKeyBlob.h
//  Dcs
//
//  Created by 赵利 on 16/10/27.
//  Copyright © 2016年 cn.dacas. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECCPublicKeyBlob : NSObject
/**
 判断当前参数是否合法

 @return yes合法，no不合法
 */
-(BOOL)isValid;

/**
 设置xCoordinate

 @param xCoordinate xCoordinate
 */
-(void)setxCoordinate:(NSData *)xCoordinate;
/**
 设置yCoordinate

 @param yCoordinate yCoordinate
 */
-(void)setyCoordinate:(NSData *)yCoordinate;
/**
 获取xCoordinate
 
 @return xCoordinate
 */
-(NSData*)getxCoordinate;
/**
 获取yCoordinate
 
 @return yCoordinate
 */
-(NSData*)getyCoordinate;

/**
 将对象转为字节

 @return 字节串
 */
-(NSData *)toByteArray;
/**
 将NSData转为EccPublicKeyBlob

 @param pubKey 公钥比特
 @return EccPublicKeyBlob对象
 */
-(BOOL) readFromByteArray:(NSData *)pubKey;
/**
 将当前对象转为字符串
 
 @return 对象的字符串输出
 */
-(NSString*)toString;
@end
