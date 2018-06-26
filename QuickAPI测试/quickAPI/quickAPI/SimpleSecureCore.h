//
//  SimpleSecureCore.h
//  quickAPI
//
//  Created by SecureChip on 2018/1/30.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <MultiKey/MultiKey.h>

@interface SimpleSecureCore : NSObject
+(instancetype)getinstance;
-(SecureCoreDevice*)getDefaultDevice; 

/**
 初始化
 
 @param appID ：认证用的appID
 @param appSecret :认证用的appSecret
 @param IP : 网址
 @param port ：服务器端口
 */
-(void)init:(NSString*)appID appSecret:(NSString*)appSecret IP:(NSString*)IP port:(NSInteger)port;


/**
 获取appID
 
 @return 返回appID
 */
-(NSString*)getAppID;


/**
 获取AppSecret
 
 @return 返回AppSecret
 */
-(NSString*)getAppSecret;


/**
 获取服务器信息Addr
 
 @return Addr
 */
-(ServerInfo*)getAddr;


/**
 随机生成ECC公钥
 
 @return ECC公钥
 */
-(ECCPublicKeyBlob*)getRandPublicKey;


/**
 随机生成签名
 
 @return ECCSignatureBlob对象
 */
-(ECCSignatureBlob*)getRandSignature;


/**
 随机生成对称密钥参数
 
 @return 合法的对称密钥参数
 */
-(BlockCipherParam*)getRandBlockCipherParam;


/**
 获取随机long值
 
 @return 返回随机long值
 */
-(long)getRandLong;


/**
 获取随机 NSData 数组，可固定长度或者随机长度
 
 @param fixedLength 是否固定长度
 @param maxLen 最大长度
 @return 随机 NSData 数组
 */
-(NSData*)getRand:(BOOL)fixedLength maxLen:(NSInteger)maxLen;


/**
 获取PIN
 
 @return PIN
 */
-(NSString *)getDefaultPIN;


/**
 获取公钥
 
 @param isSign 是否为签名公钥
 @return 公钥
 */
-(ECCPublicKeyBlob*)getPublicKey:(BOOL)isSign;


/**
 获取签名公钥
 
 @param keyAlias 密钥别名
 @return 公钥
 */
//-(SM2PublicKey*)getSignPublicKey:(NSString*)keyAlias;


/**
 获取加密公钥
 
 @param keyAlias 密钥别名
 @return 公钥
 */
//-(SM2PublicKey*)getEncPublicKey:(NSString*)keyAlias;


/**
 获取公钥
 
 @param isSign 是否为签名公钥
 @return 公钥
 */
-(ECCPublicKeyBlob*)getServerPublicKey:(BOOL)isSign;


/**
 清空容器，删除所有app
 */
-(void)cleanDevice;


/**
 清空app（未使用）
 */
-(void)cleanApplication;


/**
 获取默认应用
 
 @return 默认应用
 */
-(SCApplication*)getDefaultApplication;

-(SCApplication*)getEnginInitApplication;

/**
 导入ECC 密钥对
 
 @param conName 容器名
 @param publicKey 公钥
 @param privateKey 私钥
 @return 结果码
 */
-(ResultCode)importEccKeyPair:(NSString*)conName publicKey:(NSData*)publicKey privateKey:(NSData*)privateKey;


/**
 获取本地默认容器
 
 @return 默认容器
 */
-(id<IContainer,ISignKey>)getDefaultContainer;


/**
 获取协作容器
 
 @return 协作容器
 */
-(id<IContainer,ISignKey>)getDefaultRemoteContainer;
@end
