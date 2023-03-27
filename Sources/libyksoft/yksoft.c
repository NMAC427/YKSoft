//
//  yksoft.c
//  Emulate a hardware yubikey token in HOTP mode.
//  
//
//  Created by Nicolas Camenisch on 22.03.23.
//

#include "yksoft.h"
#include "yubikey.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define random_fill(_buff, _len) arc4random_buf(_buff, _len);

static inline uint32_t random_uint32(void) {
    uint32_t ret;
    random_fill(&ret, sizeof(ret));
    return ret;
}

yk_token_t yk_generate_new_token() {
    yk_token_t token;
    
    // Public ID
    struct { uint16_t a; uint32_t b; } __attribute__((packed)) rid;
    rid.a = 0x2222;    /* dddd in modhex */
    rid.b = random_uint32();
    memcpy(token.public_id, (uint8_t *)&rid, sizeof(token.public_id));
    
    // Private ID
    random_fill(token.token.uid, sizeof(token.token.uid));
    
    // AES Key
    random_fill(token.aes_key, sizeof(token.aes_key));
    
    // Rest
    token.token.ctr = 1;    // First power on
    token.token.use = 1;    // First session
    
    token.created = time(NULL);
    token.lastuse = token.created;
    
    token.ponrand = random_uint32() & 0xfffffff0;   // Fudge the time, so not all tokens are synced to time()
    
    uint64_t hztime = token.ponrand % 0xffffff;     // 24bit wrap
    
    token.token.tstpl = hztime & 0xffff;
    token.token.tstph = (hztime >> 16) & 0xff;
    token.token.rnd = random_uint32();
    
    return token;
}

int yk_update_data(yk_token_t *token) {
    time_t now = time(NULL);
    int ret = 0;
    
    // Too many session uses, increment the main counter
    if (token->token.use == 0xff) {
        token->token.ctr += 1;
        
        if (token->token.ctr == 0x7fff) {
            // Token counter at max, token must be regenerated
            return -1;
        }
        
        token->ponrand = random_uint32();
        token->token.use = 1;   // Reset session use counter
        ret = 1;    // Tell caller that we wrapped
    } else {
        token->token.use += 1;
    }
    
    // We go to great lengths to be lazy and not have to figure out the high precision time functions for the platform.
again:
    if (token->lastuse == now) {
        if ((token->ponrand & 0x0000000f) > 6) {
            // Wait one sec before generatign new token
            sleep(1);
            now = time(NULL);
            token->ponrand &= 0xfffffff0;     // Clear 8hz nibble
            goto again;
        } else {
            token->ponrand += 1;
        }
    } else {
        token->lastuse = now;
        token->ponrand &= 0xfffffff0;       // Clear 8hz nibble
    }
    
    // Figure out 8hz time
    uint64_t hztime = (now - token->created) * 8;
    hztime += token->ponrand;
    hztime %= 0xffffff;    /* 24bit wrap */
    
    token->token.tstpl = hztime & 0xffff;
    token->token.tstph = (hztime >> 16) & 0xff;
    token->token.rnd = random_uint32();
    
    return ret;
}

char* yk_generate_otp(yk_token_t *token) {
    int ret_update_data = yk_update_data(token);
    if (ret_update_data < 0) {
        return NULL;
    }
    
    // For some reason yubikey_generate messes up the token struct.
    // Therefor we need to create a copy of it to generate the OTP.
    yk_token_t copy = *token;
    
    copy.token.crc = ~yubikey_crc16((void*)&copy.token, sizeof(copy.token) - sizeof(copy.token.crc));
    
    char* otp = malloc((YUBIKEY_UID_SIZE * 2) + YUBIKEY_OTP_SIZE + 1);
    yubikey_modhex_encode(otp, (char const *)copy.public_id, sizeof(copy.public_id));
    yubikey_generate((void*)&copy.token, copy.aes_key, otp + (YUBIKEY_UID_SIZE * 2));

    return otp;
}

char* yk_token_public_id(yk_token_t *token) {
    char* buffer = malloc((sizeof(token->public_id) * 2) + 1);
    yubikey_modhex_encode(buffer, (const char*)token->public_id, sizeof(token->public_id));
    return buffer;
}

char* yk_token_private_id(yk_token_t *token) {
    char* buffer = malloc((sizeof(token->token.uid) * 2) + 1);
    yubikey_hex_encode(buffer, (const char*)token->token.uid, sizeof(token->token.uid));
    return buffer;
}

char* yk_token_aes_key(yk_token_t *token) {
    char* buffer = malloc((sizeof(token->aes_key) * 2) + 1);
    yubikey_hex_encode(buffer, (const char*)token->aes_key, sizeof(token->aes_key));
    return buffer;
}
