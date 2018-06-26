//
//  StringUtils.h
//  QuickAPITests
//
//  Created by FanGuang on 2017/12/7.
//  Copyright © 2017年 FanGuang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface StringUtils : NSObject
+(NSData *)hexStrToData:(NSString *)str;
+(NSString *)dataToHexStr:(NSData *)data;
@end
