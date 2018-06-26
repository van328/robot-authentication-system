//
//  ErrorUtil.m
//  SecurityCoreFullSDK
//
//  Created by 赵利 on 2017/12/19.
//  Copyright © 2017年 赵利. All rights reserved.
//

#import "ErrorUtil.h"
#import <MultiKey/resultCode.h>
#define CustomErrorDomain @"quickapi"
@implementation ErrorUtil
+(NSError*)geterrorWithCode:(NSInteger)errCode errorMessage:(NSString *)message{
    
    NSDictionary*userinfo=[NSDictionary dictionaryWithObject:message forKey:NSLocalizedDescriptionKey];
    return [NSError errorWithDomain:CustomErrorDomain code:errCode userInfo:userinfo];
}
+(NSError*)geterrorWithCode:(NSInteger)errCode{
    NSString *errorMessage = [resultCode toString:errCode];
    NSDictionary*userinfo=[NSDictionary dictionaryWithObject:errorMessage forKey:NSLocalizedDescriptionKey];
    return [NSError errorWithDomain:CustomErrorDomain code:errCode userInfo:userinfo];
}
@end
