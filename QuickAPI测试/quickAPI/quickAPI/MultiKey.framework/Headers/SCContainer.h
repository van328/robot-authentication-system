//
//  SCContainer.h
//  SecurecoreMoreKey
//
//  Created by SecureChip on 2018/1/3.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IContainer.h"
#import "ISignKey.h"
#import "SCElement.h"
@interface SCContainer : SCElement<IContainer,ISignKey>
-(instancetype)initWithHandle:(NSInteger)handle parent:(id<IElement>)parent name:(NSString *)Name;
@end
