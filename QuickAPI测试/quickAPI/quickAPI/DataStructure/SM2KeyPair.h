//
//  SM2KeyPair.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Key.h"
@interface SM2KeyPair : NSObject<Key>
/**
 获取SM2密钥对实例

 @param publicKey 公钥
 @param privateKey 私钥
 @param privateAlias 私钥别名
 @return SM2密钥对实例
 */
-(instancetype)initWithPublicKey:(NSData *)publicKey PrivateKey:(NSData *)privateKey PrivateAlias:(NSString *)privateAlias;
/**
 获取公钥

 @return 公钥
 */
- (NSData *)getPublicKey ;

/**
 设置公钥

 @param publicKey 公钥
 */
-(void)setPublicKey:(NSData *) publicKey ;

/**
 获取私钥

 @return 私钥
 */
- (NSData *) getPrivateKey ;

/**
 设置私钥

 @param privateKey 私钥
 */
- (void) setPrivateKey:(NSData *) privateKey ;

/**
 获取私钥别名

 @return 私钥别名
 */
- (NSString *) getPrivateAlias ;

/**
 设置私钥别名

 @param privateAlias 私钥别名
 */
- (void) setPrivateAlias:(NSString *) privateAlias ;
@end
