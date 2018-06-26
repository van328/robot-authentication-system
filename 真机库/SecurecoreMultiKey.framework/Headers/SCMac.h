//
//  SCMac.h
//  SecurecoreMoreKey
//
//  Created by SecureChip on 2018/1/5.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IMac.h"
#import "SCElement.h"
@interface SCMac : SCElement<IMac>
-(instancetype)initWithHandle:(NSInteger)handle parent:(id<IElement>)parent name:(NSString *)Name;
@end
