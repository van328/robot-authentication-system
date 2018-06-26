//
//  SCApplication.h
//  SecurecoreMoreKey
//
//  Created by SecureChip on 2018/1/2.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IApplication.h"
#import "SCElement.h"
@interface SCApplication : SCElement<IApplication>
-(instancetype)initWithHandle:(NSInteger)handle parent:(id<IElement>)parent name:(NSString *)Name;
@end
