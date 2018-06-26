//
//  SCSession.h
//  SecurecoreMoreKey
//
//  Created by SecureChip on 2018/1/5.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ISessionKey.h"
#import "SCElement.h"
@interface SCSession : SCElement<ISessionKey>
-(instancetype)initWithSessionHandle:(NSInteger)handle parent:(id<IElement>)parent;
@end
