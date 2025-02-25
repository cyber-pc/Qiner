#pragma once

#include <stdio.h>
#include <cstring>

static void hexToByte(const char* hex, uint8_t* byte, const int sizeInByte)
{
    for (int i = 0; i < sizeInByte; i++){
        sscanf(hex+i*2, "%2hhx", &byte[i]);
    }
}

static void byteToHex(const uint8_t* byte, char* hex, const int sizeInByte) {
    for (int i = 0; i < sizeInByte; i++) {
        sprintf(hex + i * 2, "%02x", byte[i]);
    }
    hex[sizeInByte * 2] = '\0'; // Null-terminate the string
}