//
//  SMAlgorithm.h
//  SecurityCoreSDK
//
//  Created by 赵利 on 2017/11/7.
//  Copyright © 2017年 赵利. All rights reserved.
//

#ifndef SMAlgorithm_h
#define SMAlgorithm_h
typedef NS_ENUM(NSInteger, Algorithm) {
    Unknown = 0,
    SGD_SM4=0x00000400,
    SGD_SM4_ECB=0x00000401,
    SGD_SM4_CBC=0x00000402,
    SGD_SM4_CFB=0x00000404,
    SGD_SM4_OFB=0x00000408,
    SGD_SM4_MAC=0x00000410,
    
    //公钥密码算法
    SGD_SM2=0x00020100,          //SM2椭圆曲线密码算法
    SGD_SM2_1=0x00020200,          //SM2椭圆曲线签名算法
    SGD_SM2_2=0x00020400,          //SM2椭圆曲线密钥交换协议
    SGD_SM2_3=0x00020800,          //SM2椭圆曲线加密算法
    
    //杂凑算法
    SGD_SM3=0x00000001,
    
    //签名算法
    SGD_SM3_SM3=0x00020201          //基于SM3算法和SM2算法的签名
    
};

#endif /* SMAlgorithm_h */
