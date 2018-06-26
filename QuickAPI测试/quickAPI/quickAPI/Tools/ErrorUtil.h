//
//  ErrorUtil.h
//  SecurityCoreFullSDK
//
//  Created by 赵利 on 2017/12/19.
//  Copyright © 2017年 赵利. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ErrorUtil : NSObject
+(NSError*)geterrorWithCode:(NSInteger)errCode errorMessage:(NSString *)message;
//+(NSError*)geterrorWithCode:(NSInteger)errCode;
@end
