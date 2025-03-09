#pragma once

#include "CustomMining.h"

#include <atomic>
#include <mutex>
#include <queue>
#include <memory>
#include <thread>


class Dispatcher
{
public:
    Dispatcher();
    ~Dispatcher();
    // Stop function
    void stop();

    // Launch the dispatcher thread that constantly send the job to network or send to a specific nodeip:port
    // This function also can simulate the dispatcher that broadcast the custom message so we don't need to wait
    // for message from node
    int launchDispatcherThread(const char* signingSeed, const char* nodeip, int port);

    // Launch the dispatcher thread that constantly listen to the XMR jobs
    int launchXMRTaskReceiverThread(int port);

    // Status thread
    int launchTaskTrackerThread();

private:

    int xmrTaskReceiverThread(int port);
    int dispatcherThread(const char* signingSeed, const char* nodeip, int port);
    int taskTrackerThread();

    std::atomic<int> _state;
    unsigned long long _taskIndex;
    //
    std::vector<std::unique_ptr<std::thread>> _threadsVec;

    // Task that send to the network
    std::mutex _jobsQueueMtx;
    std::queue<CustomTask> _jobsQueue;
    unsigned long long _dispatchedJobsCount;
};

