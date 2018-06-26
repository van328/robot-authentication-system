//
//  IClose.h
//  sctest_morekey
//
//  Created by SecureChip on 2017/12/27.
//  Copyright © 2017年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "resultCode.h"
/**
 * 密码对象关闭接口
 * Created by Nick on 2017/3/10.
 */
@protocol IClose <NSObject>
/**
 * 关闭句柄
 *
 * @return 结果码
 */

-(ResultCode) SKF_CloseHandle;
@end
