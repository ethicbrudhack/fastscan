// ===============================
// keccak_fixed.h - POPRAWNA IMPLEMENTACJA KECCAK-256
// ===============================

#ifndef KECCAK_FIXED_H
#define KECCAK_FIXED_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KECCAK_RATE 136

static inline uint64_t rotl64_keccak_fixed(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void keccak_f1600_fixed(uint64_t state[25]) {
    uint64_t bc[5];
    uint64_t t;
    int round, i, j;
    
    // Round constants
    static const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808AULL, 0x8000000080008000ULL,
        0x000000000000808BULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008AULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000AULL,
        0x000000008000808BULL, 0x800000000000008BULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800AULL, 0x800000008000000AULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };
    
    // Rotation constants
    static const int rho[24] = {
         1,  3,  6, 10, 15, 21,
        28, 36, 45, 55,  2, 14,
        27, 41, 56,  8, 25, 43,
        62, 18, 39, 61, 20, 44
    };
    
    // Pi mapping
    static const int pi[24] = {
        10,  7, 11, 17, 18,  3,
         5, 16,  8, 21, 24,  4,
        15, 23, 19, 13, 12,  2,
        20, 14, 22,  9,  6,  1
    };
    
    for (round = 0; round < 24; round++) {
        // Theta
        for (i = 0; i < 5; i++) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64_keccak_fixed(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }
        
        // Rho and Pi
        t = state[1];
        for (i = 0; i < 24; i++) {
            int idx = pi[i];
            uint64_t current = state[idx];
            state[idx] = rotl64_keccak_fixed(t, rho[i]);
            t = current;
        }
        
        // Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = state[j + i];
            }
            for (i = 0; i < 5; i++) {
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        
        // Iota
        state[0] ^= RC[round];
    }
}

void keccak_256_fixed(const unsigned char* input, size_t input_len, unsigned char output[32]) {
    uint64_t state[25] = {0};
    unsigned char block[KECCAK_RATE];
    size_t block_size = 0;
    size_t i;
    
    // Absorb
    for (i = 0; i < input_len; i++) {
        block[block_size++] = input[i];
        if (block_size == KECCAK_RATE) {
            for (int j = 0; j < KECCAK_RATE / 8; j++) {
                uint64_t lane;
                memcpy(&lane, block + j * 8, 8);
                state[j] ^= lane;
            }
            keccak_f1600_fixed(state);
            block_size = 0;
        }
    }
    
    // Padding
    block[block_size++] = 0x01;
    if (block_size == KECCAK_RATE) {
        for (int j = 0; j < KECCAK_RATE / 8; j++) {
            uint64_t lane;
            memcpy(&lane, block + j * 8, 8);
            state[j] ^= lane;
        }
        keccak_f1600_fixed(state);
        block_size = 0;
    }
    
    while (block_size < KECCAK_RATE - 1) {
        block[block_size++] = 0x00;
    }
    block[KECCAK_RATE - 1] = 0x80;
    
    // Final absorb
    for (int j = 0; j < KECCAK_RATE / 8; j++) {
        uint64_t lane;
        memcpy(&lane, block + j * 8, 8);
        state[j] ^= lane;
    }
    keccak_f1600_fixed(state);
    
    // Squeeze (first 32 bytes)
    memcpy(output, state, 32);
}

#ifdef __cplusplus
}
#endif

#endif // KECCAK_FIXED_H
