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

#include "RequestResponseHeader.h"
#include "RelayMessage.h"
#include "K12AndKeyUtil.h"
#include "keyUtils.h"


class Job
{
public:
    static constexpr const size_t kMaxBlobSize = 408;
    static constexpr const size_t kMaxSeedSize = 32;

    uint32_t m_algorithm;
    bool m_nicehash     = false;
    uint32_t m_seed[64];
    size_t m_size       = 0;
    uint32_t m_backend  = 0;
    uint64_t m_diff     = 0;
    uint64_t m_height   = 0;
    uint64_t m_target   = 0;
    uint8_t m_blob[kMaxBlobSize]{ 0 };
    uint8_t m_index     = 0;

    uint8_t m_ephPublicKey[32]{};
    uint8_t m_ephSecretKey[32]{};

    bool m_hasMinerSignature = false;
};

class JobMessage
{
public:
    unsigned long long _index;
    Job _job;
};


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

#define BROADCAST_MESSAGE 1

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

struct Miner
{
    long long data[DATA_LENGTH];
    unsigned char computorPublicKey[32];
    unsigned char currentRandomSeed[32];

    void initialize(unsigned char randomSeed[32])
    {
        random(randomSeed, randomSeed, (unsigned char*)data, sizeof(data));
        for (unsigned long long i = 0; i < DATA_LENGTH; i++)
        {
            data[i] = (data[i] >= 0 ? 1 : -1);
        }

        memcpy(currentRandomSeed, randomSeed, sizeof(currentRandomSeed));
        memset(computorPublicKey, 0, sizeof(computorPublicKey));
    }

    void getComputorPublicKey(unsigned char computorPublicKey[32])
    {
        memcpy(computorPublicKey, this->computorPublicKey, sizeof(this->computorPublicKey));
    }

    void setComputorPublicKey(unsigned char computorPublicKey[32])
    {
        memcpy(this->computorPublicKey, computorPublicKey, sizeof(this->computorPublicKey));
    }

    struct
    {
        long long input[DATA_LENGTH + NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH];
    } neurons;
    struct
    {
        unsigned long long signs[(DATA_LENGTH + NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH) * NUMBER_OF_NEIGHBOR_NEURONS / 64];
        unsigned long long sequence[MAX_DURATION];
        // Use for randomly select skipped ticks
        unsigned long long skipTicksNumber[NUMBER_OF_OPTIMIZATION_STEPS];
    } synapses;

    // Save skipped ticks
    long long skipTicks[NUMBER_OF_OPTIMIZATION_STEPS];

    // Contained all ticks possible value
    long long ticksNumbers[MAX_DURATION];

    // Main function for mining
    bool findSolution(unsigned char nonce[32])
    {
        _rdrand64_step((unsigned long long*)&nonce[0]);
        _rdrand64_step((unsigned long long*)&nonce[8]);
        _rdrand64_step((unsigned long long*)&nonce[16]);
        _rdrand64_step((unsigned long long*)&nonce[24]);
        random2(computorPublicKey, nonce, (unsigned char*)&synapses, sizeof(synapses));

        unsigned int score = 0;
        long long tailTick = MAX_DURATION - 1;
        for (long long tick = 0; tick < MAX_DURATION; tick++)
        {
            ticksNumbers[tick] = tick;
        }

        for (long long l = 0; l < NUMBER_OF_OPTIMIZATION_STEPS; l++)
        {
            skipTicks[l] = -1LL;
        }

        // Calculate the score with a list of randomly skipped ticks. This list grows if an additional skipped tick
        // does not worsen the score compared to the previous one.
        // - Initialize skippedTicks = []
        // - First, use all ticks. Compute score0 and update the score with score0.
        // - In the second run, ignore ticks in skippedTicks and try skipping a random tick 'a'.
        //    + Compute score1.
        //    + If score1 is not worse than score, add tick 'a' to skippedTicks and update the score with score1.
        //    + Otherwise, ignore tick 'a'.
        // - In the third run, ignore ticks in skippedTicks and try skipping a random tick 'b'.
        //    + Compute score2.
        //    + If score2 is not worse than score, add tick 'b' to skippedTicks and update the score with score2.
        //    + Otherwise, ignore tick 'b'.
        // - Continue this process iteratively.
        unsigned long long numberOfSkippedTicks = 0;
        long long skipTick = -1;
        for (long long l = 0; l < NUMBER_OF_OPTIMIZATION_STEPS; l++)
        {
            memset(&neurons, 0, sizeof(neurons));
            memcpy(&neurons.input[0], data, sizeof(data));

            for (long long tick = 0; tick < MAX_DURATION; tick++)
            {
                // Check if current tick should be skipped
                if (tick == skipTick)
                {
                    continue;
                }

                // Skip recorded skipped ticks
                bool tickShouldBeSkipped = false;
                for (long long tickIdx = 0; tickIdx < numberOfSkippedTicks; tickIdx++)
                {
                    if (skipTicks[tickIdx] == tick)
                    {
                        tickShouldBeSkipped = true;
                        break;
                    }
                }
                if (tickShouldBeSkipped)
                {
                    continue;
                }

                // Compute neurons
                const unsigned long long neuronIndex = DATA_LENGTH + synapses.sequence[tick] % (NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH);
                const unsigned long long neighborNeuronIndex = (synapses.sequence[tick] / (NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH)) % NUMBER_OF_NEIGHBOR_NEURONS;
                unsigned long long supplierNeuronIndex;
                if (neighborNeuronIndex < NUMBER_OF_NEIGHBOR_NEURONS / 2)
                {
                    supplierNeuronIndex = (neuronIndex - (NUMBER_OF_NEIGHBOR_NEURONS / 2) + neighborNeuronIndex + (DATA_LENGTH + NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH)) % (DATA_LENGTH + NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH);
                }
                else
                {
                    supplierNeuronIndex = (neuronIndex + 1 - (NUMBER_OF_NEIGHBOR_NEURONS / 2) + neighborNeuronIndex + (DATA_LENGTH + NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH)) % (DATA_LENGTH + NUMBER_OF_HIDDEN_NEURONS + DATA_LENGTH);
                }
                const unsigned long long offset = neuronIndex * NUMBER_OF_NEIGHBOR_NEURONS + neighborNeuronIndex;

                if (!(synapses.signs[offset / 64] & (1ULL << (offset % 64))))
                {
                    neurons.input[neuronIndex] += neurons.input[supplierNeuronIndex];
                }
                else
                {
                    neurons.input[neuronIndex] -= neurons.input[supplierNeuronIndex];
                }

                if (neurons.input[neuronIndex] > 1)
                {
                    neurons.input[neuronIndex] = 1;
                }
                if (neurons.input[neuronIndex] < -1)
                {
                    neurons.input[neuronIndex] = -1;
                }
            }

            // Compute the score
            unsigned int currentScore = 0;
            for (unsigned long long i = 0; i < DATA_LENGTH; i++)
            {
                if (data[i] == neurons.input[DATA_LENGTH + NUMBER_OF_HIDDEN_NEURONS + i])
                {
                    currentScore++;
                }
            }

            // Update score if below satisfied
            // - This is the first run without skipping any ticks
            // - Current score is not worse than previous score
            if (skipTick == -1 || currentScore >= score)
            {
                score = currentScore;
                // For the first run, don't need to update the skipped ticks list
                if (skipTick != -1 )
                {
                    skipTicks[numberOfSkippedTicks] = skipTick;
                    numberOfSkippedTicks++;
                }
            }

            // Randomly choose a tick to skip for the next round and avoid duplicated pick already chosen one
            long long randomTick = synapses.skipTicksNumber[l] % (MAX_DURATION - l);
            skipTick = ticksNumbers[randomTick];
            // Replace the chosen tick position with current tail to make sure if this tick is not chosen again
            // the skipTick is still not duplicated with previous ones.
            ticksNumbers[randomTick] = ticksNumbers[tailTick];
            tailTick--;

        }

        // Check score
        if (score >= SOLUTION_THRESHOLD)
        {
            return true;
        }

        return false;
    }
};

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

int miningThreadProc()
{
    std::unique_ptr<Miner> miner(new Miner());
    miner->initialize(randomSeed);
    miner->setComputorPublicKey(computorPublicKey);

    std::array<unsigned char, 32> nonce;
    while (!state)
    {
        if (miner->findSolution(nonce.data()))
        {
            {
                std::lock_guard<std::mutex> guard(foundNonceLock);
                foundNonce.push(nonce);
            }
            numberOfFoundSolutions++;
        }

        numberOfMiningIterations++;
    }
    return 0;
}

class ServerSocket
{
public:
#ifdef _MSC_VER
    ServerSocket()
    {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~ServerSocket()
    {
        WSACleanup();
    }

    void closeConnection()
    {
        closesocket(serverSocket);
    }

    bool establishConnection(char* address, int nodePortCustom)
    {
        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET)
        {
            printf("Fail to create a socket (%d)!\n", WSAGetLastError());
            return false;
        }

        sockaddr_in addr;
        ZeroMemory(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(nodePortCustom);
        sscanf_s(address, "%hhu.%hhu.%hhu.%hhu", &addr.sin_addr.S_un.S_un_b.s_b1, &addr.sin_addr.S_un.S_un_b.s_b2, &addr.sin_addr.S_un.S_un_b.s_b3, &addr.sin_addr.S_un.S_un_b.s_b4);
        if (connect(serverSocket, (const sockaddr*)&addr, sizeof(addr)))
        {
            printf("Fail to connect to %d.%d.%d.%d (%d)!\n", addr.sin_addr.S_un.S_un_b.s_b1, addr.sin_addr.S_un.S_un_b.s_b2, addr.sin_addr.S_un.S_un_b.s_b3, addr.sin_addr.S_un.S_un_b.s_b4, WSAGetLastError());
            closeConnection();
            return false;
        }

        return true;
    }

    SOCKET serverSocket;
#else
    void closeConnection()
    {
        close(serverSocket);
    }
    bool establishConnection(const char* address, int nodePortCustom = -1)
    {
        int port = nodePortCustom > 0 ? nodePortCustom : gNodePort;
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1)
        {
            printf("Fail to create a socket (%d)!\n", errno);
            return false;
        }

        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, address, &addr.sin_addr) <= 0)
        {
            printf("Invalid address/ Address not supported (%s)\n", address);
            return false;
        }

        if (connect(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            printf("Fail to connect to %s (%d)\n", address, errno);
            closeConnection();
            return false;
        }

        return true;
    }

    int serverSocket;
#endif

    bool sendData(char* buffer, unsigned int size)
    {
        while (size)
        {
            int numberOfBytes;
            if ((numberOfBytes = send(serverSocket, buffer, size, 0)) <= 0)
            {
                return false;
            }
            buffer += numberOfBytes;
            size -= numberOfBytes;
        }

        return true;
    }
    bool receiveData(char* buffer, unsigned int size)
    {
        const auto beginningTime = std::chrono::steady_clock::now();
        unsigned long long deltaTime = 0;
        while (size && deltaTime <= 2000)
        {
            int numberOfBytes;
            if ((numberOfBytes = recv(serverSocket, buffer, size, 0)) <= 0)
            {
                return false;
            }
            buffer += numberOfBytes;
            size -= numberOfBytes;
            deltaTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - beginningTime).count();
        }

        return true;
    }
};

static void hexToByte(const char* hex, uint8_t* byte, const int sizeInByte)
{
    for (int i = 0; i < sizeInByte; i++){
        sscanf(hex+i*2, "%2hhx", &byte[i]);
    }
}

constexpr int MESSAGE_TYPE_SOLUTION = 0;
constexpr int MESSAGE_TYPE_CUSTOM_MINING_TASK = 1;
constexpr int MESSAGE_TYPE_CUSTOM_MINING_SOLUTION = 2;

std::queue<JobMessage> jobsQueue;
std::mutex jobsQueueMtx;

enum TaskThreadId
{
    ARB_TASK_SERVER = 0, // thread that waiting for task from xmrig
    ARB_TASK_DISPATCHER = 1, // thread distribute the task to the node
    ARB_TASK_TRACKER = 2, // thread track/log the task dispatching status
    MAX_THREAD,
};


class CustomMiningTaskMessage
{

public:
    CustomMiningTaskMessage() = default;

    RequestResponseHeader header;
    Message message;
    // Payload
    std::vector<char> payload;

    unsigned char signature[64];

    size_t serialize(char* buffer) const
    {
        memcpy(buffer, &header, sizeof(RequestResponseHeader));
        memcpy(buffer + sizeof(RequestResponseHeader), (char*)&message, sizeof(message));
        memcpy(buffer + sizeof(RequestResponseHeader) + sizeof(message) , (char*)&payload[0], payload.size());
        memcpy(buffer + sizeof(RequestResponseHeader) + sizeof(message) + payload.size(), signature, sizeof(signature));

        return getTotalSizeInBytes();
    }

    size_t getTotalSizeInBytes() const
    {
        return sizeof(RequestResponseHeader) + sizeof(message) + sizeof(signature) + payload.size();
    }
};

int craftTaskMessage(
    const unsigned char* signingSubseed,
    const unsigned char* signingPublicKey,
    const JobMessage& jobBuffer,
    CustomMiningTaskMessage& taskMessage)
{
    // Payload
    taskMessage.payload.resize(sizeof(Job) + 8);
    // First 8 bytes of payload are used as task index
    memcpy(&taskMessage.payload[0], (char*)&jobBuffer._index, 8);
    memcpy(&taskMessage.payload[8], (char*)&jobBuffer._job, sizeof(Job));

    // Header
    taskMessage.header.setSize(taskMessage.getTotalSizeInBytes());
    taskMessage.header.zeroDejavu();
    taskMessage.header.setType(BROADCAST_MESSAGE);

    memcpy(taskMessage.message.sourcePublicKey, signingPublicKey, sizeof(taskMessage.message.sourcePublicKey));

    // Zero destination is used for custom mining
    memset(taskMessage.message.destinationPublicKey, 0, sizeof(taskMessage.message.destinationPublicKey));

    unsigned char sharedKeyAndGammingNonce[64];
    // Default behavior when provided seed is just a signing address
    // first 32 bytes of sharedKeyAndGammingNonce is set as zeros
    memset(sharedKeyAndGammingNonce, 0, 32);

    // Last 32 bytes of sharedKeyAndGammingNonce is randomly created so that gammingKey[0] = MESSAGE_TYPE_CUSTOM_MINING_TASK
    unsigned char gammingKey[32];
    do
    {
        _rdrand64_step((unsigned long long*) & taskMessage.message.gammingNonce[0]);
        _rdrand64_step((unsigned long long*) & taskMessage.message.gammingNonce[8]);
        _rdrand64_step((unsigned long long*) & taskMessage.message.gammingNonce[16]);
        _rdrand64_step((unsigned long long*) & taskMessage.message.gammingNonce[24]);
        memcpy(&sharedKeyAndGammingNonce[32], taskMessage.message.gammingNonce, 32);
        KangarooTwelve(sharedKeyAndGammingNonce, 64, gammingKey, 32);
    }
    while (gammingKey[0] != MESSAGE_TYPE_CUSTOM_MINING_TASK);

    // Encrypt the message payload
    std::vector<unsigned char> gamma(taskMessage.payload.size());
    KangarooTwelve(gammingKey, sizeof(gammingKey), &gamma[0], gamma.size());
    for (unsigned int i = 0; i < gamma.size(); i++)
    {
        taskMessage.payload[i] = taskMessage.payload[i] ^ gamma[i];
    }

    // Sign the message
    uint8_t digest[32] = {0};
    uint8_t signature[64] = {0};
    KangarooTwelve(
        (unsigned char*)&taskMessage.payload[0],
        taskMessage.payload.size(),
        digest,
        32);
    sign(signingSubseed, signingPublicKey, digest, signature);
    memcpy(taskMessage.signature, signature, 64);

    return 0;
}

size_t gTotalDispatchedTasks = 0;
int taskDispatcherThread(const char* signingSeed, const char* nodeip, int port)
{
    // Data for signing the the monero task
    unsigned char signingPrivateKey[32];
    unsigned char signingSubseed[32];
    unsigned char signingPublicKey[32];
    getSubseedFromSeed((unsigned char*)signingSeed, signingSubseed);
    getPrivateKeyFromSubSeed(signingSubseed, signingPrivateKey);
    getPublicKeyFromPrivateKey(signingPrivateKey, signingPublicKey);

    char publicIdentity[128] = {0};
    getIdentityFromPublicKey(signingPublicKey, publicIdentity, false);

    ServerSocket serverSocket;
    bool haveTask = false;
    std::vector<char> serializedData;
    while (!state)
    {
        bool haveTask = false;
        JobMessage jobBuffer;
        {
            std::lock_guard<std::mutex> lock(jobsQueueMtx);
            haveTask = jobsQueue.size() > 0;
            if (haveTask)
            {
                jobBuffer = jobsQueue.front();
            }
        }

        if (haveTask)
        {
            if (serverSocket.establishConnection(nodeip, port))
            {
                // Craft the task message
                CustomMiningTaskMessage taskMessage;
                craftTaskMessage(signingSubseed, signingPublicKey, jobBuffer, taskMessage);

                // Send the job to node
                serializedData.resize(taskMessage.getTotalSizeInBytes());
                taskMessage.serialize(&serializedData[0]);

                if (serverSocket.sendData((char*)&serializedData[0], serializedData.size()))
                {
                    std::lock_guard<std::mutex> lock(jobsQueueMtx);
                    // Send job successfully. Remove it from the queue
                    jobsQueue.pop();
                    gTotalDispatchedTasks++;
                }
                serverSocket.closeConnection();
            }
        }
    }

    return 0;
}

int taskReceiverThread(int port)
{
    int server_fd, moneroSocket;
    sockaddr_in address;
    int addrlen = sizeof(address);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        return -1;
    }

    // Bind address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return -1;
    }

    // Listen for connection
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        return -1;
    }

    std::cout << "Waiting for a connection ... at port " << port << std::endl;

    // Listenning to task from xmrig
    bool connectionFailure = false;
    while (!state)
    {
        // Accept new connection
        moneroSocket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (moneroSocket < 0)
        {
            perror("Accept failed");
            continue;
        }
        std::cout<< "Client connected!" << std::endl;

        bool reconnectFlag = false;
        while (!state)
        {
            // Receive task
            RelayMessage relayMessage;

            // Receive the fixed-size header safely
            int totalHeaderReceived = 0;
            while (totalHeaderReceived < sizeof(RequestResponseHeader))
            {
                int chunk = recv(moneroSocket, (char*)&relayMessage.header + totalHeaderReceived,
                                sizeof(RequestResponseHeader) - totalHeaderReceived, 0);
                if (chunk <= 0)
                {
                    std::cerr << "Client disconnected or error while receiving header.\n";
                    reconnectFlag = true;
                    break;
                }
                totalHeaderReceived += chunk;
            }

            if (connectionFailure || reconnectFlag)
            {
                break;
            }

            // Process payload
            if (!reconnectFlag)
            {
                // Get payload size from the header
                size_t payloadSize = relayMessage.header.size() - sizeof(RequestResponseHeader);

                if (payloadSize != sizeof(Job))
                {
                    std::cout << "Mismatched data size! (size =  " << payloadSize << " vs " << sizeof(Job) << std::endl;
                    continue;
                }

                // Receive the payload
                relayMessage.payload.resize(payloadSize);
                std::fill(relayMessage.payload.begin(), relayMessage.payload.end(), 0);
                size_t totalReceived = 0;
                while (totalReceived < payloadSize)
                {
                    int chunk = recv(moneroSocket, &relayMessage.payload[0] + totalReceived, payloadSize - totalReceived, 0);
                    if (chunk <= 0)
                    {
                        std::cerr << "Client disconnected or error while receiving payload.\n";
                        reconnectFlag = true;
                        break;
                    }
                    totalReceived += chunk;
                }

                // Connection failed. Exitting
                if (connectionFailure)
                {
                    break;
                }

                // Enqueue the job
                if (!reconnectFlag)
                {
                    JobMessage jobBuffer;
                    memcpy((char*)&jobBuffer._job, &relayMessage.payload[0], relayMessage.payload.size());

                    std::lock_guard<std::mutex> lock(jobsQueueMtx);
                    jobBuffer._index = jobsQueue.size();
                    jobsQueue.push(jobBuffer);
                }
            }

            if (connectionFailure || reconnectFlag)
            {
                break;
            }
        }

        if (connectionFailure)
        {
            break;
        }

        if (reconnectFlag)
        {
            std::cout << "Reconnecting ..." << std::endl;
            close(moneroSocket);
            reconnectFlag = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(10000));
        }
    }
    close(server_fd);

    return 0;
}

int taskTrackerThread()
{
    while (!state)
    {
        size_t remainedJob = 0;
        size_t dispatchedTasks = 0;
        {
            std::lock_guard<std::mutex> lock(jobsQueueMtx);
            remainedJob = jobsQueue.size();
            dispatchedTasks = gTotalDispatchedTasks;
        }
        std::cout << "Dispatched jobs: remained(" << remainedJob << "), total (" << dispatchedTasks << ")" << std::endl;
        std::this_thread::sleep_for(std::chrono::duration < double, std::milli>(5000));
    }

    return 0;
}

int main(int argc, char* argv[])
{
    std::string mode;
    int serverPort = 0;
    int nodePort = 0;
    std::string nodeIP;
    std::string dispatcherSeed;
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
            dispatcherSeed = argv[++i];
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
        // Launch thread listen to tasks from Monero network
        taskThreads[ARB_TASK_SERVER].reset(new std::thread(taskReceiverThread, serverPort));

        // Launch thread submit job to node
        taskThreads[ARB_TASK_DISPATCHER].reset(new std::thread(taskDispatcherThread, dispatcherSeed.c_str(), nodeIP.c_str(), nodePort));

        taskThreads[ARB_TASK_TRACKER].reset(new std::thread(taskTrackerThread));
    }


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
    std::vector<std::thread> miningThreads;
    if (argc != 7)
    {
        printf("Usage:   Qiner [Node IP] [Node Port] [MiningID] [Signing Seed] [Mining Seed] [Number of threads]\n");
    }
    else
    {
        gNodeIp = argv[1];
        gNodePort = std::atoi(argv[2]);
        char* miningID = argv[3];
        printf("Qiner is launched. Connecting to %s:%d\n", gNodeIp, gNodePort);

        consoleCtrlHandler();

        {
            getPublicKeyFromIdentity(miningID, computorPublicKey);

            // Data for signing the solution
            char* signingSeed = argv[4];
            unsigned char signingPrivateKey[32];
            unsigned char signingSubseed[32];
            unsigned char signingPublicKey[32];
            char privateKeyQubicFormat[128] = {0};
            char publicKeyQubicFormat[128] = {0};
            char publicIdentity[128] = {0};
            getSubseedFromSeed((unsigned char*)signingSeed, signingSubseed);
            getPrivateKeyFromSubSeed(signingSubseed, signingPrivateKey);
            getPublicKeyFromPrivateKey(signingPrivateKey, signingPublicKey);

            //getIdentityFromPublicKey(signingPublicKey, miningID, false);

            hexToByte(argv[5], randomSeed, 32);
            unsigned int numberOfThreads = atoi(argv[6]);
            printf("%d threads are used.\n", numberOfThreads);
            miningThreads.resize(numberOfThreads);
            for (unsigned int i = numberOfThreads; i-- > 0; )
            {
                miningThreads.emplace_back(miningThreadProc);
            }
            ServerSocket serverSocket;

            auto timestamp = std::chrono::steady_clock::now();
            long long prevNumberOfMiningIterations = 0;
            while (!state)
            {
                bool haveNonceToSend = false;
                size_t itemToSend = 0;
                std::array<unsigned char, 32> sendNonce;
                {
                    std::lock_guard<std::mutex> guard(foundNonceLock);
                    haveNonceToSend = foundNonce.size() > 0;
                    if (haveNonceToSend)
                    {
                        sendNonce = foundNonce.front();
                    }
                    itemToSend = foundNonce.size();
                }
                if (haveNonceToSend)
                {
                    if (serverSocket.establishConnection(gNodeIp))
                    {
                        struct
                        {
                            RequestResponseHeader header;
                            Message message;
                            unsigned char solutionMiningSeed[32];
                            unsigned char solutionNonce[32];
                            unsigned char signature[64];
                        } packet;

                        packet.header.setSize(sizeof(packet));
                        packet.header.zeroDejavu();
                        packet.header.setType(BROADCAST_MESSAGE);

                        memcpy(packet.message.sourcePublicKey, signingPublicKey, sizeof(packet.message.sourcePublicKey));
                        memcpy(packet.message.destinationPublicKey, computorPublicKey, sizeof(packet.message.destinationPublicKey));

                        unsigned char sharedKeyAndGammingNonce[64];
                        // Default behavior when provided seed is just a signing address
                        // first 32 bytes of sharedKeyAndGammingNonce is set as zeros
                        memset(sharedKeyAndGammingNonce, 0, 32);
                        // If provided seed is the for computor public key, generate sharedKey into first 32 bytes to encrypt message
                        if (memcmp(computorPublicKey, signingPublicKey, 32) == 0)
                        {
                            getSharedKey(signingPrivateKey, computorPublicKey, sharedKeyAndGammingNonce);
                        }
                        // Last 32 bytes of sharedKeyAndGammingNonce is randomly created so that gammingKey[0] = 0 (MESSAGE_TYPE_SOLUTION)
                        unsigned char gammingKey[32];
                        do
                        {
                            _rdrand64_step((unsigned long long*) & packet.message.gammingNonce[0]);
                            _rdrand64_step((unsigned long long*) & packet.message.gammingNonce[8]);
                            _rdrand64_step((unsigned long long*) & packet.message.gammingNonce[16]);
                            _rdrand64_step((unsigned long long*) & packet.message.gammingNonce[24]);
                            memcpy(&sharedKeyAndGammingNonce[32], packet.message.gammingNonce, 32);
                            KangarooTwelve(sharedKeyAndGammingNonce, 64, gammingKey, 32);
                        } while (gammingKey[0]);

                        // Encrypt the message payload
                        unsigned char gamma[32 + 32];
                        KangarooTwelve(gammingKey, sizeof(gammingKey), gamma, sizeof(gamma));
                        for (unsigned int i = 0; i < 32; i++)
                        {
                            packet.solutionMiningSeed[i] = randomSeed[i] ^ gamma[i];
                            packet.solutionNonce[i] = sendNonce[i] ^ gamma[i + 32];
                        }

                        // Sign the message
                        uint8_t digest[32] = {0};
                        uint8_t signature[64] = {0};
                        KangarooTwelve(
                            (unsigned char*)&packet + sizeof(RequestResponseHeader),
                            sizeof(packet) - sizeof(RequestResponseHeader) - 64,
                            digest,
                            32);
                        sign(signingSubseed, signingPublicKey, digest, signature);
                        memcpy(packet.signature, signature, 64);

                        // Send message
                        if (serverSocket.sendData((char*)&packet, packet.header.size()))
                        {
                            std::lock_guard<std::mutex> guard(foundNonceLock);
                            // Send data successfully. Remove it from the queue
                            foundNonce.pop();
                            itemToSend = foundNonce.size();
                        }
                        serverSocket.closeConnection();
                    }
                }

                std::this_thread::sleep_for(std::chrono::duration < double, std::milli>(1000));

                unsigned long long delta = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - timestamp).count();
                if (delta >= 1000)
                {
                    // Get current time in UTC
                    std::time_t now_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                    std::tm* utc_time = std::gmtime(&now_time);
                    printf("|   %04d-%02d-%02d %02d:%02d:%02d   |   %llu it/s   |   %d solutions   |   %.10s...   |\n",
                        utc_time->tm_year + 1900, utc_time->tm_mon, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec,
                        (numberOfMiningIterations - prevNumberOfMiningIterations) * 1000 / delta, numberOfFoundSolutions.load(), miningID);
                    prevNumberOfMiningIterations = numberOfMiningIterations;
                    timestamp = std::chrono::steady_clock::now();
                }
            }
        }
        printf("Shutting down...Press Ctrl+C again to force stop.\n");

        // Wait for all threads to join
        for (auto& miningTh : miningThreads)
        {
            if (miningTh.joinable())
            {
                miningTh.join();
            }
        }
        printf("Qiner is shut down.\n");
    }

    return 0;
}