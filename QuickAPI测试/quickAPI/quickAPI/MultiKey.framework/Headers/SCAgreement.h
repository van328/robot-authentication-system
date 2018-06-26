//
//  SCAgreement.h
//  SecurecoreMoreKey
//
//  Created by 赵利 on 2018/1/14.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IAgreement.h"
#import "SCElement.h"
@interface SCAgreement : SCElement<IAgreement>
-(instancetype)initWithHandle:(NSInteger)handle parent:(id<IElement>)parent;
@end
