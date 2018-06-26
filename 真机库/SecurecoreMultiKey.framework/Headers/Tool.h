//
//  tools.h
//  Dcs
//
//  Created by 赵利 on 16/10/27.
//  Copyright © 2016年 cn.dacas. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Tool : NSObject

+ (NSMutableData *)convertHexStrToData:(const NSString *)str;
+(NSString *)parseByteArray2HexString:(const Byte*) bytes length:(int)length;
//10进制转16进制
+(NSString *)ToHex:(long long int)tmpid;
@end
