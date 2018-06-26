//
//  SM4Test.m
//  quickAPITests
//
//  Created by FanGuang on 2018/2/26.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "Cipher.h"
#import "SimpleSecureCore.h"
#import "defines.h"
#import "SecretKeySpec.h"
#import "IvParameterSpec.h"
@interface SM4Test : XCTestCase
@property(strong,nonatomic)SimpleSecureCore *ssc;

@end

@implementation SM4Test

- (void)setUp {
    [super setUp];
    
    
    self.ssc = [SimpleSecureCore getinstance];
    //初始化SimleSecureCore
    [self.ssc init:appID appSecret:appSecret IP:IP port:port];
}


- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
    SimpleSecureCore* ssc = [SimpleSecureCore getinstance];
    [ssc cleanDevice];
}

//MARK:-四种功能测试
- (void)testECBWithoutPadding{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"0123456789abcdeffedcba9876543210" dataUsingEncoding:NSUTF8StringEncoding];
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/ECB/NOPADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText;
    cipherText = [cipherOUT doFinal:plainText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 32);
    
    //sc解密
    Cipher* cipherIN;
    cipherIN = [Cipher getInstanceWithProvider:@"SM4/ECB/NOPADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherIN initializeWithMode:DECRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* plainText2;
    plainText2 = [cipherIN doFinal:cipherText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(plainText2);
    XCTAssertEqual(plainText2.length, 32);
    XCTAssertTrue([plainText2 isEqualToData:plainText]);
}

- (void)testECBWithPadding{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"1234567890" dataUsingEncoding:NSUTF8StringEncoding];
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/ECB/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText;
    cipherText = [cipherOUT doFinal:plainText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 16);
    
    //sc解密
    Cipher* cipherIN;
    cipherIN = [Cipher getInstanceWithProvider:@"SM4/ECB/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherIN initializeWithMode:DECRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* plainText2;
    plainText2 = [cipherIN doFinal:cipherText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(plainText2);
    XCTAssertEqual(plainText2.length, 10);
    XCTAssertTrue([plainText2 isEqualToData:plainText]);
}

- (void)testCBCWithoutPadding{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"0123456789abcdeffedcba9876543210" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* IV = [@"0000000000000000" dataUsingEncoding:NSUTF8StringEncoding];
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/NOPADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    id<AlgorithmParameterSpec> params = [[IvParameterSpec alloc]initWithIV:IV];
    [cipherOUT initializeWithParam:ENCRYPT_MODE key:key params:params err:&err];
    XCTAssertNil(err);
    NSData* cipherText;
    cipherText = [cipherOUT doFinal:plainText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 32);
    
    //sc解密
    Cipher* cipherIN;
    cipherIN = [Cipher getInstanceWithProvider:@"SM4/CBC/NOPADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherIN initializeWithParam:DECRYPT_MODE key:key params:params err:&err];
    XCTAssertNil(err);
    NSData* plainText2;
    plainText2 = [cipherIN doFinal:cipherText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(plainText2);
    XCTAssertEqual(plainText2.length, 32);
    XCTAssertTrue([plainText2 isEqualToData:plainText]);
}

- (void)testCBCWithPadding{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"1234567890" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* IV = [@"0000000000000000" dataUsingEncoding:NSUTF8StringEncoding];
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    id<AlgorithmParameterSpec> params = [[IvParameterSpec alloc]initWithIV:IV];
    [cipherOUT initializeWithParam:ENCRYPT_MODE key:key params:params err:&err];
    XCTAssertNil(err);
    NSData* cipherText;
    cipherText = [cipherOUT doFinal:plainText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 16);
    
    //sc解密
    Cipher* cipherIN;
    cipherIN = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherIN initializeWithParam:DECRYPT_MODE key:key params:params err:&err];
    XCTAssertNil(err);
    NSData* plainText2;
    plainText2 = [cipherIN doFinal:cipherText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(plainText2);
    XCTAssertEqual(plainText2.length, 10);
    XCTAssertTrue([plainText2 isEqualToData:plainText]);
}

//MARK:-函数测试
//dofinal测试
- (void)testdoFinal{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText = [cipherOUT update:plainText err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 16);
    cipherText = [cipherOUT doFinal:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 16);
}


//doFinalWithData测试
- (void)testdoFinalWithData{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText1 = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText2 = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];

    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText1 = [cipherOUT update:plainText1 err:&err];
    XCTAssertNil(err);
    NSData* cipherText2 = [cipherOUT doFinal:plainText2 err:&err];
    XCTAssertNotNil(cipherText2);
    XCTAssertEqual(cipherText2.length, 32);
}

//doFinalWithDataANDOutput测试
- (void)testdoFinalWithDataANDOutput{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText1 = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText2 = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* originalText = [@"990123456789abcdeffedcba987654321012345" dataUsingEncoding:NSUTF8StringEncoding];
    
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText1 = [cipherOUT update:plainText1 err:&err];
    XCTAssertNil(err);
    NSData* cipherText2 = [NSData dataWithData:originalText];
    NSInteger I = [cipherOUT doFinal:plainText2 output:&cipherText2 err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText2);
    XCTAssertEqual(I, 32);
    XCTAssertEqual(cipherText2.length, originalText.length);
    XCTAssertFalse([cipherText2 isEqualToData:originalText]);
}

//doFinalWithOutputOffset测试
- (void)testdoFinalWithOutputOffset{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* originalText = [@"0123456789abcdeffedcba987654321012345" dataUsingEncoding:NSUTF8StringEncoding];
    
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText1 = [cipherOUT update:plainText err:&err];
    XCTAssertNil(err);
    NSData* cipherText2 = [NSData dataWithData:originalText];
    NSInteger I = [cipherOUT doFinal:&cipherText2 outputoffset:5 err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText2);
    XCTAssertEqual(I, 16);
    XCTAssertEqual(cipherText2.length, originalText.length);
    XCTAssertFalse([cipherText2 isEqualToData:originalText]);
}

//doFinalWithInputOffset测试
- (void)testdoFinalWithInputOffset{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText1 = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText2 = [@"0001234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText1 = [cipherOUT update:plainText1 err:&err];
    XCTAssertNil(err);
    NSData* cipherText2 = [cipherOUT doFinal:plainText2 inputoffset:3 inputLen:16 err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText2);
    XCTAssertEqual(cipherText2.length, 32);
}

//doFinalWithInputOffset&Output测试
- (void)testdoFinalWithInputOffsetANDOutput{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText1 = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText2 = [@"0001234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText1 = [cipherOUT update:plainText1 err:&err];
    XCTAssertNil(err);
    NSData* Output = [@"0123456789abcdeffedcba987654321012345" dataUsingEncoding:NSUTF8StringEncoding];
    NSInteger I = [cipherOUT doFinal:plainText2 inputoffset:3 inputLen:16 output:&Output err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(Output);
    XCTAssertEqual(Output.length, 37);
    XCTAssertEqual(I, 32);
}
//doFinalWithInputOffset&OutputOffset测试
- (void)testdoFinalWithInputOffsetANDOutputOffset{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText1 = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText2 = [@"0001234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText1 = [cipherOUT update:plainText1 err:&err];
    XCTAssertNil(err);
    NSData* Output = [@"0123456789abcdeffedcba987654321012345" dataUsingEncoding:NSUTF8StringEncoding];
    NSInteger I = [cipherOUT doFinal:plainText2 inputoffset:3 inputLen:16 output:&Output outputoffset:3 err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(Output);
    XCTAssertEqual(Output.length, 37);
    XCTAssertEqual(I, 32);
}

//MARK:-update测试
- (void)testUpdateWithRange{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"123456789012345" dataUsingEncoding:NSUTF8StringEncoding];
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/ECB/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText;
    cipherText = [cipherOUT update:plainText inputOffset:3 inputLen:10 err:&err];
    XCTAssertNil(err);
    cipherText = [cipherOUT doFinal:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 16);
}

- (void)testUpdateWithOUTput{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"1234567890" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* originalText = [@"0123456789abcdeffedcba987654321012345" dataUsingEncoding:NSUTF8StringEncoding];
   
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/ECB/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText = [NSData dataWithData:originalText];
    NSInteger I = [cipherOUT update:plainText output:&cipherText err:&err];
    XCTAssertNil(err);
    cipherText = [cipherOUT doFinal:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 16);
    XCTAssertFalse([cipherText isEqualToData:originalText]);
}

- (void)testUpdateWithInputOffsetANDOUTput{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* originalText = [@"0123456789abcdeffedcba987654321012345" dataUsingEncoding:NSUTF8StringEncoding];
    
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/ECB/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText = [NSData dataWithData:originalText];
    NSInteger I = [cipherOUT update:plainText inputOffset:3 inputLen:10 output:&cipherText err:&err];
    XCTAssertNil(err);
    cipherText = [cipherOUT doFinal:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, 16);
    XCTAssertFalse([cipherText isEqualToData:originalText]);
}

- (void)testUpdateWithInputOffsetANDOUTputOffset{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* plainText = [@"12345678901234567890123" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* originalText = [@"0123456789abcdeffedcba987654321012345" dataUsingEncoding:NSUTF8StringEncoding];
    
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/ECB/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    [cipherOUT initializeWithMode:ENCRYPT_MODE key:key err:&err];
    XCTAssertNil(err);
    NSData* cipherText = [NSData dataWithData:originalText];
    NSInteger I = [cipherOUT update:plainText inputOffset:3 inputLen:16 output:&cipherText outputOffset:5 err:&err];
    XCTAssertNil(err);
    XCTAssertNotNil(cipherText);
    XCTAssertEqual(cipherText.length, originalText.length);
    XCTAssertEqual(I, 16);
    XCTAssertFalse([cipherText isEqualToData:originalText]);
}



//getIV测试
- (void)testgetIV{
    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData* IV = [@"0000000000000000" dataUsingEncoding:NSUTF8StringEncoding];
    id<Key> key;
    Cipher* cipherOUT;
    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
    //sc加密
    NSError* err;
    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    id<AlgorithmParameterSpec> params = [[IvParameterSpec alloc]initWithIV:IV];
    [cipherOUT initializeWithParam:ENCRYPT_MODE key:key params:params err:&err];
    XCTAssertNil(err);
    NSData* IVOut = [cipherOUT getIV];
    XCTAssertTrue([IVOut isEqualToData:IV]);
}

//getBLockSize测试
- (void)testgetBLockSize{
    Cipher* cipher;
    NSError* err;
    cipher = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
    XCTAssertNil(err);
    NSInteger I = [cipher getBlockSize];
    XCTAssertEqual(I, 16);
}

////getParameters测试
//- (void)testgetParameters{
//    NSData* keyBytes = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
//    NSData* IV = [@"0000000000000000" dataUsingEncoding:NSUTF8StringEncoding];
//    id<Key> key;
//    Cipher* cipherOUT;
//    key = [[SecretKeySpec alloc]initWithKey:keyBytes algorithm:@"SM4"];
//    //sc加密
//    NSError* err;
//    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
//    XCTAssertNil(err);
//    id<AlgorithmParameterSpec> params = [[IvParameterSpec alloc]initWithIV:IV];
//    [cipherOUT initializeWithParam:ENCRYPT_MODE key:key params:params err:&err];
//    XCTAssertNil(err);
//    AlgorithmParameters* paramsOut = [cipherOUT getParameters];
//    XCTAssertNotNil( paramsOut);
//}

//- (void)testMaxAllowedKeyLength{
//    Cipher* cipherOUT;
//    //sc加密
//    NSError* err;
//    cipherOUT = [Cipher getInstanceWithProvider:@"SM4/CBC/PKCS5PADDING" provider:@"SC" err:&err];
//    XCTAssertNil(err);
//    NSInteger I = [cipherOUT getMaxAllowedKeyLength:@"SM4/CBC/PKCS5PADDING" err:&err];
//    XCTAssertNil(err);
//    XCTAssertEqual(I, 16);
//}
@end
