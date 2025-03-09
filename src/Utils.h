#pragma once

#include <stdio.h>
#include <cstring>
#include <iostream>

#include "CustomMining.h"
#include "K12AndKeyUtil.h"
#include "keyUtils.h"

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

template<unsigned long long num>
bool isZeros(const unsigned char* value)
{
    bool allZeros = true;
    for (unsigned long long i = 0; i < num; ++i)
    {
        if (value[i] != 0)
        {
            return false;
        }
    }
    return true;
}
