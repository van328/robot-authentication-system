//
//  SCHash.h
//  SecurecoreMoreKey
//
//  Created by SecureChip on 2018/1/4.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IHash.h"
#import "SCElement.h"
@interface SCHash : SCElement<IHash>
-(instancetype)initWithHandle:(NSInteger)handle parent:(id<IElement>)parent;
@end
