#include <chrono>
#include <thread>
#include <mutex>
#include <cstdio>
#include <cstring>
#include <array>
#include <queue>
#include <atomic>
#include <vector>
#include <iostream>
#ifdef _MSC_VER
#include <intrin.h>
#include <winsock2.h>
#pragma comment (lib, "ws2_32.lib")

#else
#include <signal.h>
#include <immintrin.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#endif

#include <fstream>

#include "Constants.h"
#include "CustomMining.h"
#include "Dispatcher.h"
#include "PoolOperator.h"
#include "Network.h"

#include "RequestResponseHeader.h"
#include "RelayMessage.h"
#include "K12AndKeyUtil.h"
#include "keyUtils.h"

void random(unsigned char* publicKey, unsigned char* nonce, unsigned char* output, unsigned int outputSize)
{
    unsigned char state[200];
    memcpy(&state[0], publicKey, 32);
    memcpy(&state[32], nonce, 32);
    memset(&state[64], 0, sizeof(state) - 64);

    for (unsigned int i = 0; i < outputSize / sizeof(state); i++)
    {
        KeccakP1600_Permute_12rounds(state);
        memcpy(output, state, sizeof(state));
        output += sizeof(state);
    }
    if (outputSize % sizeof(state))
    {
        KeccakP1600_Permute_12rounds(state);
        memcpy(output, state, outputSize % sizeof(state));
    }
}

void random2(unsigned char* publicKey, unsigned char* nonce, unsigned char* output, unsigned int outputSize) // outputSize must be a multiple of 8
{
    unsigned char state[200];
    memcpy(&state[0], publicKey, 32);
    memcpy(&state[32], nonce, 32);
    memset(&state[64], 0, sizeof(state) - 64);

    // Data on heap to avoid stack overflow for some compiler
    std::vector<unsigned char> poolVec(1048576 + 24); // Need a multiple of 200
    unsigned char* pool = poolVec.data();

    for (unsigned int i = 0; i < poolVec.size(); i += sizeof(state))
    {
        KeccakP1600_Permute_12rounds(state);
        memcpy(&pool[i], state, sizeof(state));
    }

    unsigned int x = 0; // The same sequence is always used, exploit this for optimization
    for (unsigned long long i = 0; i < outputSize; i += 8)
    {
        *((unsigned long long*) & output[i]) = *((unsigned long long*) & pool[x & (1048576 - 1)]);
        x = x * 1664525 + 1013904223; // https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use
    }
}

typedef struct
{
    unsigned char sourcePublicKey[32];
    unsigned char destinationPublicKey[32];
    unsigned char gammingNonce[32];
} Message;

char* gNodeIp = NULL;
int gNodePort = 0;

static constexpr unsigned long long DATA_LENGTH = 256;
static constexpr unsigned long long NUMBER_OF_HIDDEN_NEURONS = 3000;
static constexpr unsigned long long NUMBER_OF_NEIGHBOR_NEURONS = 3000;
static constexpr unsigned long long MAX_DURATION = 3000*3000;
static constexpr unsigned long long NUMBER_OF_OPTIMIZATION_STEPS = 30;
static constexpr unsigned int SOLUTION_THRESHOLD = 87;

static_assert(((DATA_LENGTH + NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH)* NUMBER_OF_NEIGHBOR_NEURONS) % 64 == 0, "Synapse size need to be a multipler of 64");
static_assert(NUMBER_OF_OPTIMIZATION_STEPS < MAX_DURATION, "Number of retries need to smaller than MAX_DURATION");


static std::atomic<char> state(0);

static unsigned char computorPublicKey[32];
static unsigned char randomSeed[32];
static std::atomic<long long> numberOfMiningIterations(0);
static std::atomic<unsigned int> numberOfFoundSolutions(0);
static std::queue<std::array<unsigned char, 32>> foundNonce;
std::mutex foundNonceLock;


#ifdef _MSC_VER
static BOOL WINAPI ctrlCHandlerRoutine(DWORD dwCtrlType)
{
    if (!state)
    {
        state = 1;
    }
    else // User force exit quickly
    {
        std::exit(1);
    }
    return TRUE;
}
#else
void ctrlCHandlerRoutine(int signum)
{
    if (!state)
    {
        state = 1;
    }
    else // User force exit quickly
    {
        std::exit(1);
    }
}
#endif

void consoleCtrlHandler()
{
#ifdef _MSC_VER
    SetConsoleCtrlHandler(ctrlCHandlerRoutine, TRUE);
#else
    signal(SIGINT, ctrlCHandlerRoutine);
#endif
}

int getSystemProcs()
{
#ifdef _MSC_VER
#else
#endif
    return 0;
}

void printCustomMiningMessage(const CustomMiningTaskMessage& message)
{
    char hexStr[128] = {0};
    char publicIdentity[128] = {0};
    memset(hexStr, 0, sizeof(hexStr));
    byteToHex(message._sourcePublicKey, hexStr, 32);
    getIdentityFromPublicKey(message._sourcePublicKey, publicIdentity, false);
    if (std::strcmp(DISPATCHER, publicIdentity) == 0)
    {
        std::cout << "[OK] DISPATCHER ID " << publicIdentity << std::endl;
        std::cout << "[OK] DISPATCHER PublicKey " << hexStr << std::endl;
    }
    else
    {
        std::cout << "[FAILED] publicIdentity: " << publicIdentity << std::endl;
        return;
    }

    //
    getIdentityFromPublicKey(message._destinationPublicKey, publicIdentity, false);
    if (isZeros<32>(message._destinationPublicKey))
    {
        std::cout << "[OK] Zeros dest ID " << publicIdentity << std::endl;
    }
    else
    {
        std::cout << "[FAILED] Zeros dest ID: " << publicIdentity << std::endl;
        return;
    }

    // Task info
    CustomTask task = message._task;
    std::cout  << "Task index " << task._taskIndex << std::endl;
    std::cout  << "Target  " << task._target << std::endl;
    std::cout  << "Height " << task._height << std::endl;
    std::cout  << "ExtraNonce " << task._extraNonce << std::endl;
    memset(hexStr, 0, sizeof(hexStr));
    byteToHex(task._seed, hexStr, 32);
    std::cout  << "Seed hash " << hexStr << std::endl;
}

int readFetchingTaskBinary(const char* fileName)
{
    // Read binary data for testing
    {
        CustomMiningTaskMessage message;
        std::vector<char> serializedData(sizeof(CustomMiningTaskMessage));

        std::ifstream file(fileName, std::ios::binary);
        if (!file)
        {
            std::cerr << "Error opening file!\n";
            return -1;
        }
        file.read(reinterpret_cast<char*>(&message) + sizeof(RequestResponseHeader), sizeof(CustomMiningTaskMessage) - sizeof(RequestResponseHeader));

        printCustomMiningMessage(message);
    }
    return 0;
}

Dispatcher gDispatcher;
PoolOperator gPoolOperator;

int main(int argc, char* argv[])
{
    std::string mode;
    int serverPort = 0;
    int nodePort = 0;
    std::string nodeIP;
    std::string seed;
    std::string binFileName;
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        // Check for specific arguments
        if (arg == "--mode")
        {
            mode = argv[++i];
        }
        else if (arg == "--port")
        {
            serverPort = std::stoi(argv[++i]);
        }
        else if (arg == "--nodeport")
        {
            nodePort = std::stoi(argv[++i]);
        }
        else if (arg == "--nodeip")
        {
            nodeIP = argv[++i];
        }
        else if (arg == "--seed")
        {
            seed = argv[++i];
        }
        else if (arg == "--bin")
        {
            binFileName = argv[++i];
        }
        else
        {
            std::cout << "Unknown argument: " << arg << "\n";
        }
    }
    std::cout << "- mode: " << mode << std::endl
              << "- serverPort: " << serverPort << std::endl
              << "- nodeip: " << nodeIP << std::endl
              << "- nodeport: " << nodePort << std::endl;

    std::vector<std::unique_ptr<std::thread>> taskThreads(MAX_THREAD);

    consoleCtrlHandler();

    // Dispatcher mode
    if (mode == "dispatcher")
    {
        gDispatcher.launchXMRTaskReceiverThread(serverPort);
        gDispatcher.launchDispatcherThread(seed.c_str(), nodeIP.c_str(), nodePort);
        gDispatcher.launchTaskTrackerThread();
    }
    else if (mode == "pool")
    {
        // Launch thread receive task from node or relay
        gPoolOperator.launchTaskReceiverThread(serverPort);

        // Launch thread waif for requested task from miner
        gPoolOperator.launchTaskDistribution(serverPort);

        // Launch thread wait for solution from miner
        gPoolOperator.launchSolutionReceiverThread(serverPort);

        // Launch thread wait for solution from miner
        gPoolOperator.launchSolutionSubmitterThread(seed.c_str(), nodeIP.c_str(), nodePort);

    }
    else if(mode == "bin")
    {
        // Read a binary file dumping from node and do analysis
        readFetchingTaskBinary(binFileName.c_str());
    }

    while (!state)
    {
        std::this_thread::sleep_for(std::chrono::duration < double, std::milli>(1000));
    }

    std::cout << "Shutting down...";

    // Stop the dispatcher
    gDispatcher.stop();


    // Wait for all threads to join
    for (auto& t : taskThreads)
    {
        if (nullptr == t)
        {
            continue;
        }
        if (t->joinable())
        {
            t->join();
        }
    }
    printf("Qiner is shut down.\n");
    return 0;
}