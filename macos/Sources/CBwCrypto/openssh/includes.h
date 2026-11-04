#pragma once
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonDigest.h>
#include "../include/CBwCrypto.h"
#define explicit_bzero bw_wipe
static inline void bw_freezero(void *p, size_t n) { if (p) { bw_wipe(p, n); free(p); } }
#define freezero bw_freezero
