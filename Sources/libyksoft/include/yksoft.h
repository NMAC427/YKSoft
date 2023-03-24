//
//  yksoft.h
//  
//
//  Created by Nicolas Camenisch on 22.03.23.
//

#ifndef yksoft_h
#define yksoft_h

#include "yubikey.h"

#include <stdint.h>
#include <string.h>

typedef uint8_t yk_bytes_uid_t[YUBIKEY_UID_SIZE];
typedef uint8_t yk_bytes_key_t[YUBIKEY_KEY_SIZE];

typedef struct {
    yubikey_token_st token;                 // yubikey token type
    
    uint8_t public_id[YUBIKEY_UID_SIZE];    // 6 byte public identifier
    uint8_t aes_key[YUBIKEY_KEY_SIZE];      // 16 byte private AES key
    uint32_t ponrand;                       // Power on rand, changes whenever the session counter wraps.
    time_t created;                         // When the yubikey was first "powered on"
    time_t lastuse;                         // When the yubikey was last used.
} yk_token_t;


extern yk_token_t yk_generate_new_token();
extern int yk_update_data(yk_token_t *token);
extern char* yk_generate_otp(yk_token_t *token);

extern char* yk_token_public_id(yk_token_t *token);
extern char* yk_token_private_id(yk_token_t *token);
extern char* yk_token_aes_key(yk_token_t *token);
    
#endif /* yksoft_h */
