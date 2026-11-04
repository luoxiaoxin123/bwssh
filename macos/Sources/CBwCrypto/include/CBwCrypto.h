#pragma once
#include <stddef.h>
#include <stdint.h>
#include "../argon2/include/argon2.h"
int bcrypt_pbkdf(const char *, size_t, const uint8_t *, size_t, uint8_t *, size_t, unsigned int);
void bw_wipe(void *, size_t);
// Darwin's LOCAL_PEERPID and proc_bsdinfo are wrapped to avoid Swift ABI assumptions.
int bw_peer_pid(int fd);
int bw_process(int pid, int *parent, uint64_t *started, char *path, size_t path_size);
int bw_arguments(int pid, char *output, size_t size);
