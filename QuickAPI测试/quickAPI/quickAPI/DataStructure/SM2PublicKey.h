//
//  SM2PublicKey.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <MultiKey/MultiKey.h>
#import "PublicKey.h"
@interface SM2PublicKey : NSObject<PublicKey>
/**
 获取公钥实例

 @param publicKey 公钥数据
 @return 公钥实例
 */
-(instancetype)initWithPublicKey:(NSData *)publicKey;
/**
 获取公钥数据

 @return 公钥数据
 */
- (ECCPublicKeyBlob *)getPublicKeyBlob;

- (NSData *)toByteArray;
@end
