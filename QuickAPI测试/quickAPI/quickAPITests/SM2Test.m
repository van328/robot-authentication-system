//
//  SM2Test.m
//  quickAPITests
//
//  Created by FanGuang on 2018/2/27.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SKF_SM2Cipher.h"
#import "SKF_SM2Signer.h"
#import "SM2KeyPairParameter.h"
#import "SM2PrivateKey.h"
#import "SM2PublicKey.h"
#import "KeyPairGenerator.h"
#import "SimpleSecureCore.h"
#import "defines.h"
#import "Cipher.h"
#import "StringUtils.h"
#import "KeyPair.h"
#import "Signature.h"

@interface SM2Test : XCTestCase
@property(strong,nonatomic)SimpleSecureCore *ssc;
@end

@implementation SM2Test

- (void)setUp {
    [super setUp];
    self.ssc = [SimpleSecureCore getinstance];
    //初始化SimleSecureCore
    [self.ssc init:appID appSecret:appSecret IP:IP port:port]; 
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

//SM2加密
- (void)testSM2Cipher{
    //创建签名公私钥对，首先创建公私钥对生成器
    NSString* encPublicKey = @"04344081b80805540a38d71d721bd072d8957eae15aeb852e72086ab4c5962b89b5bb8628b9d9c4edd30f341a5a25886c063cff46dc04c7e68f2efb3b58830e0f3";
    NSData* pubkey = [StringUtils hexStrToData:encPublicKey];


    SM2PublicKey* publicKey = [[SM2PublicKey alloc] initWithPublicKey:pubkey];

    NSData* plainText  = [@"1234567890" dataUsingEncoding:NSUTF8StringEncoding];
    Cipher* cipher;
    NSError* err;
    cipher = [Cipher getInstanceWithProvider:@"SM2" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipher initializeWithMode:ENCRYPT_MODE key:publicKey err:&err];
    XCTAssertNil(err);
    NSData* cipherText = [cipher doFinal:plainText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 107);
    
}

//SM2加解密（用户从外部导入加解密密钥对）
- (void)testCipherWithoutGenerator{
    //外部导入公私钥
    NSString* encPublicKey = @"04344081b80805540a38d71d721bd072d8957eae15aeb852e72086ab4c5962b89b5bb8628b9d9c4edd30f341a5a25886c063cff46dc04c7e68f2efb3b58830e0f3";
    NSString* encPrivateKey = @"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    NSData* pubkey = [StringUtils hexStrToData:encPublicKey];
    NSData* prikey = [StringUtils hexStrToData:encPrivateKey];
    SimpleSecureCore* core = [SimpleSecureCore getinstance];
    //密钥标识
    NSString* alias = @"abc";
    //导入密钥对
    ResultCode rs = [core importEccKeyPair:alias publicKey:pubkey privateKey:prikey];
    XCTAssertTrue(rs == SAR_OK);
    SM2PublicKey* publicKey = [[SM2PublicKey alloc] initWithPublicKey:pubkey];
    SM2PrivateKey* privateKey = [[SM2PrivateKey alloc] initWithAlias:alias];
   //明文
    NSData* plainText  = [@"1234567890" dataUsingEncoding:NSUTF8StringEncoding];
    NSError* err;
    //获取Cipher实例
    Cipher* cipher = [Cipher getInstanceWithProvider:@"SM2" provider:@"SC" err:&err];
    XCTAssertNil(err);
    //以加密模式和加密公钥初始化cipher
    [cipher initializeWithMode:ENCRYPT_MODE key:publicKey err:&err];
    XCTAssertNil(err);
    //执行SM2加密操作
    NSData* cipherText = [cipher doFinal:plainText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 107);

    //以解密模式和外部密钥对初始化cipher
    [cipher initializeWithMode:DECRYPT_MODE key:privateKey err:&err];
    XCTAssertNil(err);
    //执行解密操作
    NSData* plainText2 = [cipher doFinal:cipherText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(plainText2);
    XCTAssertEqual(plainText2.length, 10);
    XCTAssertTrue([plainText2 isEqualToData:plainText]);
}

//SM2加解密（用户生成加解密密钥对）
- (void)testCipherWithGenerator{
    //密钥对标识
    NSString* keyPairAlias = @"Crypto";
    //获取KeyPairGenerator实例，用于生成SM2加解密密钥对
    KeyPairGenerator* keyPairGenerator  = [KeyPairGenerator getInstance:@"SM2Cipher" provider:@"SC"];
    //设置密钥生成参数
    SM2KeyPairParameter* sm2KeyPairParameter = [[SM2KeyPairParameter alloc]initWithAlias:keyPairAlias];
    NSError* err;
    //初始化keyPairGenerator
    [keyPairGenerator initialize:sm2KeyPairParameter err:&err];
    XCTAssertNil(err);
    ////生成SM2加密密钥对
    KeyPair* keypair = [keyPairGenerator generateKeyPair];
    //原文
    NSData* text = [@"1234567890" dataUsingEncoding:NSUTF8StringEncoding];
    //获取Cipher实例
    Cipher* cipher = [Cipher getInstanceWithProvider:@"SM2" provider:@"SC" err:&err];
    XCTAssertNil(err);
    //以加密模式和生成的公钥初始化cipher
    [cipher initializeWithMode:ENCRYPT_MODE key:[keypair getPublic] err:&err];
    XCTAssertNil(err);
    //加密
    NSData* cipherText = [NSData new];
    NSInteger I = [cipher doFinal:text output:&cipherText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 107);
    XCTAssertEqual(I, 107);
    
    //以解密模式和生成的私钥初始化cipher
    [cipher initializeWithMode:DECRYPT_MODE key:[keypair getPrivate] err:&err];
    XCTAssertNil(err);
    //解密(有outputoffset的dofinal: output长度有要求)
    NSData* output = [@"0000000000000000000000000000000000000000" dataUsingEncoding:NSUTF8StringEncoding];
    I = [cipher doFinal:cipherText inputoffset:0 inputLen:cipherText.length output:&output outputoffset:3 err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(output);
    XCTAssertEqual(output.length, 40);
    NSData* plainText = [output subdataWithRange:NSMakeRange(3, 10)];
    XCTAssertTrue([plainText isEqualToData:text]);
    XCTAssertEqual(I, 10);
}


//SM2签名、验签
- (void)testSignature{
    //创建签名公私钥对，首先创建公私钥对生成器
    NSString* keyPairAlias = @"Signature";
    NSData* text = [@"123456" dataUsingEncoding:NSUTF8StringEncoding];
    KeyPairGenerator* keyPairGenerator;
    keyPairGenerator = [KeyPairGenerator getInstance:@"SM2Signature" provider:@"SC"];
    SM2KeyPairParameter* sm2KeyPairParameter = [[SM2KeyPairParameter alloc]initWithAlias:keyPairAlias];
    NSError* err;
    //秘钥生成器初始化
    [keyPairGenerator initialize:sm2KeyPairParameter err:&err];
    XCTAssertNil(err);
    //生成签名密钥对
    KeyPair* keypair = [keyPairGenerator generateKeyPair];
    //获取Signature对象实例
    Signature* signature = [Signature getInstanceWithProvider:@"SM2" provider:@"SC" err:&err];
    XCTAssertNil(err);
    //设置signature为签名模式
    [signature initSign:[[SM2PrivateKey alloc] initWithAlias:keyPairAlias] err:&err];
    XCTAssertNil(err);
    //把待签名数据写入缓冲区
    [signature updataWithData:text err:&err];
    XCTAssertNil(err);
    [signature updata:'b' err:&err];
    XCTAssertNil(err);
    [signature updata:text off:2 len:2 err:&err];
    XCTAssertNil(err);
    //数据缓冲结束，进行签名
    NSData* sign = [signature sign:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(sign);
    XCTAssertEqual(sign.length, 64);
    
    //设置signature为验签模式
    SM2PublicKey* sm2PublicKey = (SM2PublicKey*)[keypair getPublic];
    [signature initVerify:sm2PublicKey err:&err];
    XCTAssertNil(err);
    //把待验签数据写入缓冲区
    [signature updataWithData:text err:&err];
    XCTAssertNil(err);
    [signature updata:'b' err:&err];
    XCTAssertNil(err);
    [signature updata:text off:2 len:2 err:&err];
    XCTAssertNil(err);
    //数据缓冲结束，开始验证签名
    BOOL rs =  [signature verify:sign err:&err];
    XCTAssertNil(err);
    XCTAssertTrue(rs);
}


//SM2签名、验签--error:未初始化
- (void)testSignatureError1{
    //创建签名公私钥对，首先创建公私钥对生成器
    NSString* keyPairAlias = @"Signature";
    NSData* text = [@"123456" dataUsingEncoding:NSUTF8StringEncoding];
    KeyPairGenerator* keyPairGenerator;
    keyPairGenerator = [KeyPairGenerator getInstance:@"SM2Signature" provider:@"SC"];
    SM2KeyPairParameter* sm2KeyPairParameter = [[SM2KeyPairParameter alloc]initWithAlias:keyPairAlias];
    NSError* err;
    //秘钥生成器初始化
    [keyPairGenerator initialize:sm2KeyPairParameter err:&err];
    XCTAssertNil(err);
    //生成签名密钥对
    KeyPair* keypair = [keyPairGenerator generateKeyPair];
    //获取Signature对象实例
    Signature* signature = [Signature getInstanceWithProvider:@"SM2" provider:@"SC" err:&err];
    XCTAssertNil(err);
    //设置signature为签名模式
//    [signature initSign:[[SM2PrivateKey alloc] initWithAlias:keyPairAlias] err:&err];
//    XCTAssertNil(err);
    //把待签名数据写入缓冲区
    [signature updataWithData:text err:&err];
    XCTAssertEqual(err.code, SAR_NOTINITIALIZEERR);

}
@end
