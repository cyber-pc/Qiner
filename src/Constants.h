#pragma once

#include <cstdint>
#include <cstddef>

#define DISPATCHER "XPXYKFLGSWRHRGAUKWFWVXCDVEYAPCPCNUTMUDWFGDYQCWZNJMWFZEEGCFFO"
// Fake DISPATCHER of aaaa...
//#define DISPATCHER "BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK"
#define BROADCAST_MESSAGE 1
#define P2P 1
#define REQUEST_CUSTOM_MINING_QUEUE 56

constexpr int DEFAULT_PORT = 21841;
constexpr int MESSAGE_TYPE_SOLUTION = 0;
constexpr int MESSAGE_TYPE_CUSTOM_MINING_TASK = 1;
constexpr int MESSAGE_TYPE_CUSTOM_MINING_SOLUTION = 2;
constexpr int SIGNATURE_SIZE = 64;

// Dummy define for testing pool operator
// Those define will not work when comunicating to node
constexpr int MESSAGE_TYPE_MINER_TASK = 1;
constexpr int MESSAGE_TYPE_MINER_SOLUTION = 2;

constexpr int MAX_MINERS_CONNECTION = 1024;
constexpr unsigned long long MAX_BLOB_SIZE = 408;
constexpr unsigned long long MAX_SEED_SIZE = 32;

enum TaskThreadId
{
    ARB_TASK_SERVER = 0, // thread that waiting for task from xmrig
    ARB_TASK_DISPATCHER = 1, // thread distribute the task to the node
    ARB_TASK_TRACKER = 2, // thread track/log the task dispatching status
    POOL_TASK_FETCHER = 3,
    MAX_THREAD,
};
