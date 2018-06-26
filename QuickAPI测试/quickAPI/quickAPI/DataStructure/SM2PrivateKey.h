//
//  SM2PrivateKey.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PrivateKey.h"
@interface SM2PrivateKey : NSObject<PrivateKey>
/**
 获取SM2私钥实例

 @param privateKeyAlias 私钥别名
 @return SM2私钥实例
 */
- (instancetype)initWithAlias:(NSString *)privateKeyAlias;
/**
 获取私钥别名

 @return 私钥别名
 */
- (NSString *)getPrivateKeyAlias;
@end
