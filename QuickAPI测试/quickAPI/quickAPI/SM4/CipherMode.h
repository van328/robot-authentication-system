//
//  CipherMode.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/7.
//  Copyright © 2018年 IIE. All rights reserved.
//

#ifndef CipherMode_h
#define CipherMode_h
typedef NS_ENUM(NSInteger, CipherMode) {
    ENCRYPT_MODE = 1,
    DECRYPT_MODE = 2,
    UNWRAP_MODE = 4,
    WRAP_MODE= 3,
};

#endif /* CipherMode_h */
