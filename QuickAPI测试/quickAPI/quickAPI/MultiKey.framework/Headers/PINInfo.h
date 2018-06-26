//
//  PINInfo.h
//  securityBaseApp
//
//  Created by 赵利 on 2017/6/27.
//  Copyright © 2017年 赵利. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PINInfo : NSObject
@property(nonatomic,assign,readonly)int mMaxRetryCount;

@property(nonatomic,assign,readonly)int mRemainRetryCount;

@property(nonatomic,assign,readonly)BOOL mDefaultPIN;
-(instancetype)initWithMaxretry:(int)retrycount remainRetrycount:(int)remaincount defaultPin:(BOOL)defaultPin;
@end
