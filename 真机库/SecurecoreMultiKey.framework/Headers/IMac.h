//
//  IMac.h
//  sctest_morekey
//
//  Created by SecureChip on 2017/12/28.
//  Copyright © 2017年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IElement.h"
#import "resultCode.h"
/**
 * 消息鉴别码运算接口
 * Created by Nick on 2017/3/2.
 */
@protocol IMac <IElement>
/**
 * 计算消息鉴别码并输出结果
 *
 * @param data 待计算的数据
 * @return 消息鉴别码
 * @throws SecureCoreException 计算中出现的异常
 */
-(NSData*)SKF_Mac:(NSData*)data err:(NSError**)err;
/**
 * 计算消息鉴别码（不输出结果）
 *
 * @param data 待计算的数据
 * @return 结果码
 */
-(ResultCode)SKF_MacUpdate:(NSData*)data;
/**
 * 完成消息鉴别码计算，输出消息鉴别码
 *
 * @return 消息鉴别码
 * @throws SecureCoreException 计算中出现的异常
 */
-(NSData*)SKF_MacFinal:(NSError**)err;

@end
