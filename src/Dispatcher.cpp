#include "Dispatcher.h"
#include "keyUtils.h"
#include "K12AndKeyUtil.h"
#include "Network.h"
#include "RelayMessage.h"

#include <vector>
#include <thread>

int craftTaskMessage(
    const unsigned char* signingSubseed,
    const unsigned char* signingPublicKey,
    const CustomTask& job,
    CustomMiningTaskMessage& taskMessage)
{
    // Header
    taskMessage._header.setSize(taskMessage.getTotalSizeInBytes());
    taskMessage._header.zeroDejavu();
    taskMessage._header.setType(BROADCAST_MESSAGE);

    memcpy(taskMessage._sourcePublicKey, signingPublicKey, sizeof(taskMessage._sourcePublicKey));

    // Zero destination is used for custom mining
    memset(taskMessage._destinationPublicKey, 0, sizeof(taskMessage._destinationPublicKey));

    // Payload
    memcpy(&taskMessage._task, &job, sizeof(taskMessage._task));

    // Sign the message
    uint8_t digest[32] = {0};
    uint8_t signature[64] = {0};
    KangarooTwelve(
        (unsigned char*)&taskMessage + sizeof(RequestResponseHeader),
        taskMessage.getTotalSizeInBytes() - sizeof(RequestResponseHeader) - SIGNATURE_SIZE,
        digest,
        32);
    sign(signingSubseed, signingPublicKey, digest, signature);
    memcpy(taskMessage._signature, signature, 64);

    return 0;
}

Dispatcher::Dispatcher()
{
    _state = 0;
    _taskIndex = 0;
}

Dispatcher::~Dispatcher()
{
    stop();
}

void Dispatcher::stop()
{
    _state.store(1);

    // Wait for all threads finished
    for (auto& t : _threadsVec)
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
}

int Dispatcher::launchDispatcherThread(const char* signingSeed, const char* nodeip, int port)
{
    // Launch thread submit job to node
    _threadsVec.emplace_back(new std::thread(&Dispatcher::dispatcherThread, this, signingSeed, nodeip, port));
    return 0;
}

int Dispatcher::launchTaskTrackerThread()
{
    _threadsVec.emplace_back(new std::thread(&Dispatcher::taskTrackerThread, this));
    return 0;
}

int Dispatcher::launchXMRTaskReceiverThread(int port)
{
    _threadsVec.emplace_back(new std::thread(&Dispatcher::xmrTaskReceiverThread, this, port));
    return 0;
}

int Dispatcher::dispatcherThread(const char* signingSeed, const char* nodeip, int port)
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
    while (!_state.load())
    {
        bool haveTask = false;
        CustomTask jobBuffer;
        {
            std::lock_guard<std::mutex> lock(_jobsQueueMtx);
            haveTask = _jobsQueue.size() > 0;
            if (haveTask)
            {
                jobBuffer = _jobsQueue.front();
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
                    std::lock_guard<std::mutex> lock(_jobsQueueMtx);
                    // Send job successfully. Remove it from the queue
                    _jobsQueue.pop();
                    _dispatchedJobsCount++;
                }
                serverSocket.closeConnection();
            }
            else
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }
    }

    return 0;
}

int Dispatcher::xmrTaskReceiverThread(int port)
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
    while (!_state.load())
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
        while (!_state.load())
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
                    CustomTask jobBuffer;
                    //memcpy((char*)&jobBuffer._job, &relayMessage.payload[0], relayMessage.payload.size());
                    jobBuffer.extractFromJob(*(Job*)(&relayMessage.payload[0]));
                    //std::cout << "jobBuffer TX " << jobBuffer._height << std::endl;

                    std::lock_guard<std::mutex> lock(_jobsQueueMtx);
                    jobBuffer._taskIndex = _taskIndex++;
                    _jobsQueue.push(jobBuffer);
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

int Dispatcher::taskTrackerThread()
{
    while (!_state.load())
    {
        size_t remainedJob = 0;
        size_t dispatchedTasks = 0;
        {
            std::lock_guard<std::mutex> lock(_jobsQueueMtx);
            remainedJob = _jobsQueue.size();
            dispatchedTasks = _dispatchedJobsCount;
        }
        std::cout << "Dispatched jobs: remained(" << remainedJob << "), total (" << dispatchedTasks << ")" << std::endl;
        std::this_thread::sleep_for(std::chrono::duration < double, std::milli>(5000));
    }

    return 0;
}