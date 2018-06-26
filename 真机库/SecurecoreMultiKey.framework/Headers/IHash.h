//
//  IHash.h
//  sctest_morekey
//
//  Created by SecureChip on 2017/12/28.
//  Copyright © 2017年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IElement.h"
#import "resultCode.h"

@protocol IHash <IElement>
/**
 * 杂凑计算并输出结果
 *
 * @param data 待计算的数据
 * @return 杂凑值
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_Digest:(NSData*)data err:(NSError**)err;
/**
 * 杂凑计算，不输出结果
 *
 * @param data 待计算的数据
 * @return 结果码
 */
-(ResultCode)SKF_DigestUpdate:(NSData*)data;
/**
 * 完成杂凑计算，输出结果
 *
 * @return 杂凑值
 * @throws SecureCoreException 运算中的异常
 */
-(NSData*)SKF_DigestFinal:(NSError**)err;

@end
