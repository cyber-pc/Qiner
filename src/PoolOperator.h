#pragma once

#include "CustomMining.h"
#include "Network.h"

#include <atomic>
#include <mutex>
#include <queue>
#include <memory>
#include <thread>


class PoolOperator
{
public:
    PoolOperator();
    ~PoolOperator();

    // Listen to the tasks and enqueue it
    // To receive the broadcast message from node, make sure you adding your IP into
    // node list somehow a refresh peer is neccessary (F4)
    int launchTaskReceiverThread(int port);

    // Submit solutions to operator
    int launchSolutionReceiverThread(int port);

    // Distribute task to miners
    int launchTaskDistribution(int port);

    // Send solution to the network
    int launchSolutionSubmitterThread(const char* computorSeed, const char* ip, int port);

    // Stop function
    void stop();

private:

    int taskReceiverThread(int port);
    int distributeTask(int port);
    int receiveSolution(int port);
    int submitSolutionToNetwork(const char* computorSeed, const char* ip, int port);

    std::atomic<int> _state;
    unsigned long long _taskIndex;

    std::vector<std::unique_ptr<std::thread>> _threadsVec;

    std::unique_ptr<ServerSocket2> _pTaskReceiverServer;

    // Task that received from the network
    std::mutex _jobsQueueMtx;
    std::queue<CustomTask> _jobsQueue;
    unsigned long long _receivedJobsCount;
    std::unique_ptr<ServerSocket2> _pTaskDistributorServer;

    // Solution that received from miner
    std::mutex _solutionsQueueMtx;
    std::queue<CustomSolution> _solutionsQueue;
    unsigned long long _receivedSolutionsCount;
    std::unique_ptr<ServerSocket2> _pSolutionServer;

    // Solutions submitter to the network
    std::unique_ptr<ServerSocket2> _pSolutionSubmitter;
};