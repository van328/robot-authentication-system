//
//  FileAttribute.h
//  securityBaseApp
//
//  Created by 赵利 on 2017/6/27.
//  Copyright © 2017年 赵利. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface FileAttribute : NSObject
@property(nonatomic,copy)NSString *FileName;
    
@property(nonatomic,assign)long FileSize;
    
@property(nonatomic,assign)long ReadRights;
    
@property(nonatomic,assign)long WriteRights;
@end
