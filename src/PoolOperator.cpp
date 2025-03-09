#include "PoolOperator.h"
#include "Network.h"
#include "keyUtils.h"


int craftSolutionMessage(
    const unsigned char* signingSubseed,
    const unsigned char* signingPublicKey,
    const CustomSolution& solution,
    CustomMiningSolutionMessage& solutionMessage)
{
    // Header
    solutionMessage._header.setSize(solutionMessage.getTotalSizeInBytes());
    solutionMessage._header.zeroDejavu();
    solutionMessage._header.setType(BROADCAST_MESSAGE);

    memcpy(solutionMessage._sourcePublicKey, signingPublicKey, sizeof(solutionMessage._sourcePublicKey));

    // Zero destination is used for custom mining
    memset(solutionMessage._destinationPublicKey, 0, sizeof(solutionMessage._destinationPublicKey));

    // Payload
    memcpy(&solutionMessage._solution, &solution, sizeof(solutionMessage._solution));

    unsigned char sharedKeyAndGammingNonce[64];
    // Default behavior when provided seed is just a signing address
    // first 32 bytes of sharedKeyAndGammingNonce is set as zeros
    memset(sharedKeyAndGammingNonce, 0, 32);

    // Last 32 bytes of sharedKeyAndGammingNonce is randomly created so that gammingKey[0] = 0 (MESSAGE_TYPE_SOLUTION)
    unsigned char gammingKey[32];
    do
    {
        _rdrand64_step((unsigned long long*) & solutionMessage._gammingNonce[0]);
        _rdrand64_step((unsigned long long*) & solutionMessage._gammingNonce[8]);
        _rdrand64_step((unsigned long long*) & solutionMessage._gammingNonce[16]);
        _rdrand64_step((unsigned long long*) & solutionMessage._gammingNonce[24]);

        memcpy(&sharedKeyAndGammingNonce[32], solutionMessage._gammingNonce, 32);
        KangarooTwelve(sharedKeyAndGammingNonce, 64, gammingKey, 32);
    } while (gammingKey[0] != MESSAGE_TYPE_CUSTOM_MINING_SOLUTION);

    // Sign the message
    uint8_t digest[32] = {0};
    uint8_t signature[64] = {0};
    KangarooTwelve(
        (unsigned char*)&solutionMessage + sizeof(RequestResponseHeader),
        solutionMessage.getTotalSizeInBytes() - sizeof(RequestResponseHeader) - SIGNATURE_SIZE,
        digest,
        32);
    sign(signingSubseed, signingPublicKey, digest, signature);
    memcpy(solutionMessage._signature, signature, 64);

    return 0;
}

PoolOperator::PoolOperator()
{
    _state = 0;
    _taskIndex = 0;
    _receivedJobsCount = 0;
}

PoolOperator::~PoolOperator()
{
    stop();
}

void PoolOperator::stop()
{
    _state = 1;
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

// Listen to the tasks and enqueue it
int PoolOperator::launchTaskReceiverThread(int port)
{
    _threadsVec.emplace_back(new std::thread(&PoolOperator::taskReceiverThread, this, port));
    return 0;
}

// Distribute task to miner
int PoolOperator::launchTaskDistribution(int port)
{
    _threadsVec.emplace_back(new std::thread(&PoolOperator::distributeTask, this, port));
    return 0;
}

// Received solutions from miner
int PoolOperator::launchSolutionReceiverThread(int port)
{
    _threadsVec.emplace_back(new std::thread(&PoolOperator::receiveSolution, this, port));
    return 0;
}

// Send solution to the network
int PoolOperator::launchSolutionSubmitterThread(const char* computorSeed, const char* ip, int port)
{
    _threadsVec.emplace_back(new std::thread(&PoolOperator::submitSolutionToNetwork, this, computorSeed, ip, port));
    return 0;
}

int PoolOperator::taskReceiverThread(int port)
{
    _pTaskReceiverServer.reset(new ServerSocket2(port));

    // Listen for connection
    if (_pTaskReceiverServer->listenForConnection() < 0)
    {
        _pTaskReceiverServer->closeSocket();
        return -1;
    }

    // Listenning to task from a node
    bool connectionFailure = false;
    while (!_state.load())
    {
        // Accept new connection
        if (_pTaskReceiverServer->acceptConnection() < 0)
        {
            perror("Accept failed");
            continue;
        }
        std::cout<< "Client connected!" << std::endl;

        bool reconnectFlag = false;
        while (!_state.load())
        {
            CustomMiningTaskMessage taskMessage;

            // Receive the fixed-size header safely
            int totalHeaderReceived = 0;
            while (totalHeaderReceived < sizeof(RequestResponseHeader))
            {
                int chunk = _pTaskReceiverServer->receiveData((char*)&taskMessage._header + totalHeaderReceived,
                                sizeof(RequestResponseHeader) - totalHeaderReceived);
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
                // Check if the message is broadcasted message
                if (taskMessage._header.type() != BROADCAST_MESSAGE)
                {
                    continue;
                }

                // Get payload size from the header. Temprary skip this because the size of its is not correct (lack of blob size)
                // size_t payloadSize = taskMessage._header.size() - sizeof(RequestResponseHeader);
                // if (payloadSize != sizeof(CustomMiningTaskMessage) - sizeof(RequestResponseHeader))
                // {
                //     std::cout << "Mismatched data size! (size =  " << payloadSize << " vs " << sizeof(CustomMiningTaskMessage) - sizeof(RequestResponseHeader) << std::endl;
                //     continue;
                // }
                size_t payloadSize = sizeof(CustomMiningTaskMessage) - sizeof(RequestResponseHeader);

                // Receive the remained payload
                size_t totalReceived = 0;
                while (totalReceived < payloadSize)
                {
                    int chunk = _pTaskReceiverServer->receiveData((char*)&taskMessage + sizeof(RequestResponseHeader) + totalReceived, payloadSize - totalReceived);
                    if (chunk <= 0)
                    {
                        std::cerr << "Client disconnected or error while receiving payload.\n";
                        reconnectFlag = true;
                        break;
                    }
                    totalReceived += chunk;
                }

                if (totalReceived != payloadSize)
                {
                    continue;
                }

                // Connection failed. Exiting
                if (connectionFailure)
                {
                    break;
                }

                // Check if the message is custom mining specific message
                char publicIdentity[128] = {0};
                getIdentityFromPublicKey(taskMessage._sourcePublicKey, publicIdentity, false);
                if (std::strcmp(DISPATCHER, publicIdentity) != 0)
                {
                    std::cout << "[FAILED] publicIdentity: " << publicIdentity << std::endl;
                    continue;
                }

                //
                getIdentityFromPublicKey(taskMessage._destinationPublicKey, publicIdentity, false);
                if (!isZeros<32>(taskMessage._destinationPublicKey))
                {
                    std::cout << "[FAILED] Zeros dest ID: " << publicIdentity << std::endl;
                    continue;
                }

                // Verify the signature of the message
                // [TODO] Fix this, currently, in core, the header's size is not the same with payload size.
                // The signature is note generated from payload only, so below code is a workaround
                const unsigned int messageSizeBug = taskMessage._header.size() - sizeof(RequestResponseHeader);
                unsigned char digest[32];
                const unsigned char* request = (unsigned char*)&taskMessage + sizeof(RequestResponseHeader);
                KangarooTwelve(request, messageSizeBug - SIGNATURE_SIZE, digest, sizeof(digest));
                if (!verify(taskMessage._sourcePublicKey, digest, (request + (messageSizeBug - SIGNATURE_SIZE))))
                {
                    char signatureHex[64 * 2 + 1];
                    byteToHex(taskMessage._signature, signatureHex, SIGNATURE_SIZE);
                    // Print the signature for debugging
                    std::cout << "Signing failed. " << signatureHex << std::endl;
                    continue;
                }

                //  Enqueue the task
                if (!reconnectFlag)
                {
                    // std::cout << "Received custom mining task: id = "
                    //     << taskMessage._task._taskIndex
                    //     << ", target = " << taskMessage._task._target
                    //     << ", height = " << taskMessage._task._height
                    //     << std::endl;

                    // TODO: Filtering obsolte task
                    std::lock_guard<std::mutex> lock(_jobsQueueMtx);
                    _jobsQueue.push(taskMessage._task);
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
            _pTaskReceiverServer->closeSocket();
            reconnectFlag = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        }
    }
    _pTaskReceiverServer->closeConnection();
    return 0;
}

// Logic that distribute the task from external connection
// Currently it only try to dequeue the
// TODO: accept multiple external connections and verify the indentity of the connected miner
int PoolOperator::distributeTask(int port)
{
    _pTaskDistributorServer.reset(new ServerSocket2(port));

    // Listen for connection
    if (_pTaskReceiverServer->listenForConnection(MAX_MINERS_CONNECTION) < 0)
    {
        _pTaskReceiverServer->closeSocket();
        return -1;
    }

    // Listenning to request from a miner
    bool connectionFailure = false;
    while (!_state.load())
    {
        // Accept new connection
        if (_pTaskDistributorServer->acceptConnection() < 0)
        {
            perror("Accept failed");
            continue;
        }

        // This code should reflect the strategy of pool operator
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
                OperatorTaskMessage minerTaskMessage;
                minerTaskMessage._header.setType(MESSAGE_TYPE_MINER_TASK);
                minerTaskMessage._header.setSize(sizeof(OperatorTaskMessage));

                // Send the job to miner
                if (_pTaskDistributorServer->sendData((char*)&minerTaskMessage, sizeof(OperatorTaskMessage)) == sizeof(OperatorTaskMessage))
                {
                    std::lock_guard<std::mutex> lock(_jobsQueueMtx);
                    // Send job successfully. Remove it from the queue
                    _jobsQueue.pop();
                }
                _pTaskDistributorServer->closeSocket();
            }
        }

    }

    _pTaskDistributorServer->closeConnection();
    return 0;
}

// Logic that distribute the task from external connection
// Currently it only try to dequeue the
// TODO: accept multiple external connections and verify the indentity of the connected miner
int PoolOperator::receiveSolution(int port)
{
    _pSolutionServer.reset(new ServerSocket2(port));

    bool connectionFailure = false;
    while (!_state.load())
    {
        // Accept new connection
        if (_pSolutionServer->acceptConnection() < 0)
        {
            perror("Accept failed");
            continue;
        }
        std::cout<< "Client connected!" << std::endl;

        bool reconnectFlag = false;
        while (!_state.load())
        {
            OperatorSolutionMessage solutionMessage;
            int chunk = _pSolutionServer->receiveData((char*)&solutionMessage, sizeof(solutionMessage));
            if (chunk <= 0)
            {
                std::cerr << "Client disconnected or error while receiving data.\n";
                reconnectFlag = true;
                break;
            }

            if (connectionFailure || reconnectFlag)
            {
                break;
            }

            // Process payload
            if (!reconnectFlag)
            {
                // Check if the message is solution message
                if (solutionMessage._header.type() != MESSAGE_TYPE_MINER_SOLUTION)
                {
                    continue;
                }

                // TODO: Verify the correctness and Identity of the message

                //  Enqueue the task
                if (!reconnectFlag)
                {
                    // TODO: Pool need to filter correct solution, currently just keep it as it is
                    std::lock_guard<std::mutex> lock(_solutionsQueueMtx);
                    _solutionsQueue.push(solutionMessage._solution);
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
            _pTaskReceiverServer->closeSocket();
            reconnectFlag = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        }
    }
    _pTaskReceiverServer->closeConnection();

    return 0;
}

int PoolOperator::submitSolutionToNetwork(const char* computorSeed, const char* ip, int port)
{
    // Data for signing the the monero solution
    unsigned char signingPrivateKey[32];
    unsigned char signingSubseed[32];
    unsigned char signingPublicKey[32];
    getSubseedFromSeed((unsigned char*)computorSeed, signingSubseed);
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
        CustomSolution solutionBuffer;
        {
            std::lock_guard<std::mutex> lock(_solutionsQueueMtx);
            haveTask = _solutionsQueue.size() > 0;
            if (haveTask)
            {
                solutionBuffer = _solutionsQueue.front();
            }
        }

        if (haveTask)
        {
            if (serverSocket.establishConnection(ip, port))
            {
                // Craft the task message
                CustomMiningSolutionMessage  solutionMessage;
                craftSolutionMessage(signingSubseed, signingPublicKey, solutionBuffer, solutionMessage);

                // Send the job to node
                serializedData.resize(solutionMessage.getTotalSizeInBytes());
                solutionMessage.serialize(&serializedData[0]);

                if (serverSocket.sendData((char*)&serializedData[0], serializedData.size()))
                {
                    std::lock_guard<std::mutex> lock(_jobsQueueMtx);
                    // Send job successfully. Remove it from the queue
                    _jobsQueue.pop();
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