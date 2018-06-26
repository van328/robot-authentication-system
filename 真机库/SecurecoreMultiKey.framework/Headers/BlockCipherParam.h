//
//  BlockCipherParam.h
//  Dcs
//
//  Created by 赵利 on 16/10/27.
//  Copyright © 2016年 cn.dacas. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface BlockCipherParam:NSObject
@property(nonatomic,strong,readonly)NSData *iv;
@property(nonatomic,assign,readonly)NSInteger paddingType;
@property(nonatomic,assign,readonly)NSInteger feedBitLen;

/**
 * 判断分组密码参数的合法性
 *
 * @return yes合法，no不合法
 */
-(BOOL)isValid;


/**
  设置iv

 @param iv iv
 */
-(void)setiv:(NSData*)iv;
/**
  设置iFeedBitLen

 @param FeedBitLen FeedBitLen
 */
-(void)setFeedBitLen:(NSInteger)FeedBitLen;
/**
  设置PaddingType

 @param PaddingType PaddingType
 */
-(void)setPaddingType:(NSInteger)PaddingType;
@end
