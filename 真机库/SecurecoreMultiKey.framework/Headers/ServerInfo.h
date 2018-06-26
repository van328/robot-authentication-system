//
//  socketAddress.h
//  SecurityCoreSDK
//
//  Created by 赵利 on 2017/11/5.
//  Copyright © 2017年 赵利. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ServerInfo : NSObject
@property(copy,nonatomic)NSString *ip;
@property(assign,nonatomic)int port;
@end
