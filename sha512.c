#include <string.h>
#include <stdint.h> 
#include "sha512.h"

static inline u64 swap_endianness(u64 x) {
    return __builtin_bswap64(x);
}

size_t read_block(FILE* stream, u8* buffer) {
    // This assumes the buffer is exactly 128 bytes long.
    return fread(buffer, sizeof(u8), BLOCK_BYTE_SIZE, stream);
}

void pad_block(u8* buffer, size_t buffer_content_size) {
    // This assumes the buffer has at least 17 bytes of empty spaces to be padded

    buffer[buffer_content_size] = 0b10000000;
    for (size_t i = buffer_content_size + 1; i < BLOCK_BYTE_SIZE; i++) {
        buffer[i] = 0;
    }
}

void seal_block(u8* buffer, u64 message_content_size) {
    u64* padding_cursor = (u64*)(buffer + BLOCK_BYTE_SIZE - 8);
    *padding_cursor = swap_endianness(message_content_size * 8);
}

void swap_endianness_block(u64* buffer) {
    for (size_t i = 0; i < BLOCK_WORD_SIZE; i++) {
        buffer[i] = swap_endianness(buffer[i]);
    }
}

static inline u64 rotate_right(u64 x, size_t n_bits) {
    return (x >> n_bits) | (x << (64 - n_bits));
}

static inline u64 sigma_0(u64 x) {
    return rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7);
}

static inline u64 sigma_1(u64 x) {
    return rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6);
}

static inline u64 ch(u64 x, u64 y, u64 z) {
    return (x & y) ^ ((~x) & z);
}

static inline u64 maj(u64 x, u64 y, u64 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline u64 big_sigma_0(u64 x) {
    return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
}

static inline u64 big_sigma_1(u64 x) {
    return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
}

void extend_block(u64* buffer) {
    for (size_t i = BLOCK_WORD_SIZE; i < BUFFER_WORD_SIZE; i++) {
        buffer[i] = sigma_1(buffer[i - 2]) + buffer[i - 7] + sigma_0(buffer[i - 15]) + buffer[i - 16];
    }
}

void compress_block(u64* buffer, u64* registers) {
    u64 working_registers[REGISTER_SIZE];
    for (size_t i = 0; i < REGISTER_SIZE; i++) {
        working_registers[i] = registers[i];
    }
    
    for (size_t i = 0; i < BUFFER_WORD_SIZE; i++) {
        u64 t1 = working_registers[7] 
            + big_sigma_1(working_registers[4]) 
            + ch(working_registers[4], working_registers[5], working_registers[6])
            + K[i]
            + buffer[i];
        
        u64 t2 = big_sigma_0(working_registers[0]) 
            + maj(working_registers[0], working_registers[1], working_registers[2]);

        working_registers[7] = working_registers[6];
        working_registers[6] = working_registers[5];
        working_registers[5] = working_registers[4];
        working_registers[4] = working_registers[3] + t1;
        working_registers[3] = working_registers[2];
        working_registers[2] = working_registers[1];
        working_registers[1] = working_registers[0];
        working_registers[0] = t1 + t2;
    }

    for (size_t i = 0; i < REGISTER_SIZE; i++) {
        registers[i] += working_registers[i];
    }
}

u64* sha512(FILE* stream, u64* registers) {
    u64 buffer[80];
    for (size_t i = 0; i < REGISTER_SIZE; i++) {
        registers[i] = IV[i];
    }

    u64 message_content_size = 0;
    int sealed_block = 0;
    int padded_block = 0;

    while (!feof(stream)) {
        size_t buffer_content_size = read_block(stream, (u8*) buffer);
        message_content_size += (u64) buffer_content_size;

        if (buffer_content_size < BLOCK_BYTE_SIZE) {
            pad_block((u8*) buffer, buffer_content_size);
            padded_block = 1;
        }
        
        if (buffer_content_size < BLOCK_BYTE_SIZE - 16) {
            seal_block((u8*) buffer, message_content_size);
            sealed_block = 1;
        }

        swap_endianness_block(buffer);
        extend_block(buffer);
        compress_block(buffer, registers);
    }

    if ((sealed_block == 0) && (padded_block == 1)) bzero(buffer, BLOCK_BYTE_SIZE);
    if (padded_block == 0) pad_block((u8*) buffer, 0);
    if (sealed_block == 0) seal_block((u8*) buffer, message_content_size);
    if ((sealed_block == 0) || (padded_block == 0)) {
        swap_endianness_block(buffer);
        extend_block(buffer);
        compress_block(buffer, registers);
    }

    return registers;
}