//
//  EnvelopedKeyBlob.h
//  Dcs
//
//  Created by 赵利 on 16/10/27.
//  Copyright © 2016年 cn.dacas. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ECCCipherBlob.h"
#import "ECCPublicKeyBlob.h"
@interface EnvelopedKeyBlob : NSObject
@property(nonatomic,assign,readonly)NSInteger version;
@property(nonatomic,assign,readonly)NSInteger ulbits;
@property(nonatomic,assign,readonly)NSInteger ulSymmAlgID;
@property(nonatomic,strong,readonly)NSData *cbEncryptedPriKey;
@property(nonatomic,strong,readonly)ECCPublicKeyBlob *pubKey;
@property(nonatomic,strong,readonly)ECCCipherBlob *eccCiperBlob;
/**
 设置公钥

 @param pubKey 公钥
 */
-(void)setpubKey:(ECCPublicKeyBlob *)pubKey;
/**
 设置ulbits

 @param ulbits ulbits
 */
-(void)setulbits:(NSInteger)ulbits;
/**
 设置版本号

 @param version 版本号
 */
-(void)setversion:(NSInteger)version;
/**
 设置密文

 @param eccCiperBlob 密文
 */

-(void)seteccCiperBlob:(ECCCipherBlob *)eccCiperBlob;
/**
 设置密钥密文

 @param cbEncryptedPriKey 密文
 */
-(void)setcbEncryptedPriKey:(NSData *)cbEncryptedPriKey;
/**
 设置密钥id

 @param ulSymmAlgID 密钥id
 */
-(void)setulSymmAlgID:(NSInteger)ulSymmAlgID;
/**
 判断当前实例是否合法

 @return yes合法，no非法
 */
-(BOOL) isValid;

@end
