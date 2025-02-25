#pragma once

#include "Constants.h"
#include "Utils.h"
#include "RequestResponseHeader.h"
#include "K12AndKeyUtil.h"

// XMRig job
class Job
{
public:
    uint32_t m_algorithm;
    bool m_nicehash     = false;
    uint32_t m_seed[64];
    size_t m_size       = 0;
    uint32_t m_backend  = 0;
    uint64_t m_diff     = 0;
    uint64_t m_height   = 0;
    uint64_t m_target   = 0;
    uint8_t m_blob[MAX_BLOB_SIZE]{ 0 };
    uint8_t m_index     = 0;

    uint8_t m_ephPublicKey[32]{};
    uint8_t m_ephSecretKey[32]{};

    bool m_hasMinerSignature = false;
};

// Task structure received from ARB that doesn't contain the HEADER
class CustomTask
{
public:
    void extractFromJob(const Job& job)
    {
        memcpy(_blob, job.m_blob, MAX_BLOB_SIZE);
        memcpy(_seed, job.m_seed, MAX_SEED_SIZE);
        _target = job.m_target;
        _height = job.m_height;
        _extraNonce = 0;

    }

    unsigned long long _taskIndex;

    unsigned char _blob[MAX_BLOB_SIZE]; // Job data from pool
    unsigned long long _size;     // length of the blob
    unsigned long long _target;             // Pool difficulty
    unsigned long long _height;             // Block height
    unsigned char _seed[MAX_SEED_SIZE]; // Seed hash for XMR

    unsigned int _extraNonce;
};

class CustomMiningTaskMessage
{

public:
    CustomMiningTaskMessage() = default;

    RequestResponseHeader _header;

    unsigned char _sourcePublicKey[32];
    unsigned char _destinationPublicKey[32];
    unsigned char _gammingNonce[32];
    CustomTask _task;

    unsigned char _signature[SIGNATURE_SIZE];

    size_t serialize(char* buffer) const
    {
        memcpy(buffer, this, getTotalSizeInBytes());
        return getTotalSizeInBytes();
    }

    size_t getTotalSizeInBytes() const
    {
        return sizeof(CustomMiningTaskMessage);
    }
    size_t getPayLoadSize() const
    {
        return sizeof(CustomMiningTaskMessage) - sizeof(_header) - sizeof(_signature);
    }
};

constexpr size_t CUSTOM_MINING_PAYLOAD_SIZE = sizeof(CustomMiningTaskMessage) - sizeof(RequestResponseHeader);
struct TaskQueueMessage
{
    unsigned long long _taskCount;
    char _taskQueueBuffer[1024U * CUSTOM_MINING_PAYLOAD_SIZE];
};