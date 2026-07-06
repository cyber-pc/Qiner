// AntMiner: ant-colony reference miner.
//
// Validation harness for the core node's ant-colony mining: runs the full pipeline
// (query epoch context, derive the per-identity root, grind children with
// computeScoreFromParent, submit solutions, track its own growing tree).
// One coordinator thread owns all network IO; N worker threads grind nonces against a
// shared job (parent ANN + anchor digest) with one engine each and one shared 512MB pool.
// With -dummy the score engine is not used at all: random solutions are submitted to
// exercise the node's queue filter, publish gate, and reject paths.
// Usage: AntMiner [Node IP] [Node Port] [MiningID] [Signing Seed] [Threads] [-dummy]

#include <chrono>
#include <thread>
#include <mutex>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <atomic>
#include <memory>

#ifndef _MSC_VER
#include <signal.h>
#endif

#include "score_addition.h"
#include "keyUtils.h"
#include "network.h"

// Wire protocol (mirrors core/src/network_messages)

#define MESSAGE_TYPE_ANT_SOLUTION 3
#define BROADCAST_TICK 3
#define REQUEST_QUORUM_TICK 14
#define REQUEST_CURRENT_TICK_INFO 27
#define RESPOND_CURRENT_TICK_INFO 28
#define END_RESPONSE 35
#define REQUEST_ANT_MINEABLE_PARENTS 72
#define RESPOND_ANT_MINEABLE_PARENTS 73
#define REQUEST_ANT_EPOCH_CONTEXT 76
#define RESPOND_ANT_EPOCH_CONTEXT 77

#define NUMBER_OF_COMPUTORS 676

struct RespondCurrentTickInfo
{
    unsigned short tickDuration;
    unsigned short epoch;
    unsigned int tick;
    unsigned short numberOfAlignedVotes;
    unsigned short numberOfMisalignedVotes;
    unsigned int initialTick;
};
static_assert(sizeof(RespondCurrentTickInfo) == 16, "RespondCurrentTickInfo unexpected size");

struct RespondAntEpochContext
{
    unsigned char spectrumDigest[32];   // per-identity root seed; root = initializeANN(K12(pubkey || this))
    unsigned int threshold;             // addition score floor for this epoch (lowered on the test node)
    unsigned int freshnessWindow;       // N: publish within N ticks of the anchor; siblings within N coexist
    unsigned int solutionCount;         // accepted solutions so far (the tree-growth readout)
    unsigned int freeAnnSlotsCount;
    unsigned short epoch;
    unsigned short padding;
};
static_assert(sizeof(RespondAntEpochContext) == 52, "RespondAntEpochContext unexpected size");

// Quorum-tick request: returns the stored votes for a tick; a set bit in voteFlags SKIPS that
// computor's vote. Used to read the anchor tick's voted transactionDigest.
struct RequestedQuorumTick
{
    unsigned int tick;
    unsigned char voteFlags[(NUMBER_OF_COMPUTORS + 7) / 8];
};
static_assert(sizeof(RequestedQuorumTick) == 92, "RequestedQuorumTick unexpected size");

// The tick vote (response comes as BROADCAST_TICK). Only tick, epoch and transactionDigest are
// read here; the layout must stay byte-exact with core network_messages/tick.h.
struct TickVote
{
    unsigned short computorIndex;
    unsigned short epoch;
    unsigned int tick;

    unsigned short millisecond;
    unsigned char second;
    unsigned char minute;
    unsigned char hour;
    unsigned char day;
    unsigned char month;
    unsigned char year;

    unsigned int prevResourceTestingDigest;
    unsigned int saltedResourceTestingDigest;

    unsigned int prevTransactionBodyDigest;
    unsigned int saltedTransactionBodyDigest;

    unsigned char prevSpectrumDigest[32];
    unsigned char prevUniverseDigest[32];
    unsigned char prevComputerDigest[32];
    unsigned char saltedSpectrumDigest[32];
    unsigned char saltedUniverseDigest[32];
    unsigned char saltedComputerDigest[32];

    unsigned char transactionDigest[32];
    unsigned char expectedNextTickTransactionDigest[32];

    unsigned char signature[64];
};
static_assert(sizeof(TickVote) == 352, "TickVote unexpected size");

struct RequestAntMineableParents
{
    unsigned int fromIndex;
};
static_assert(sizeof(RequestAntMineableParents) == 4, "RequestAntMineableParents unexpected size");

struct RespondAntMineableParentsHeader
{
    unsigned int count;
    unsigned int itemSize;
    unsigned int nextIndex;
};
static_assert(sizeof(RespondAntMineableParentsHeader) == 12, "RespondAntMineableParentsHeader unexpected size");

struct AntMineableParent
{
    unsigned int parentTickOffset;          // the entry's own selfRef
    unsigned int parentSolutionIndexInTick;
    unsigned int parentScore;
    unsigned int siblingFloor;
    unsigned int anchorTick;
    unsigned int depth;
};
static_assert(sizeof(AntMineableParent) == 24, "AntMineableParent unexpected size");

// ROOT sentinel of a parent reference (matches core SolutionRef ROOT_REF).
static constexpr unsigned int ROOT_TICK_OFFSET = 0U;
static constexpr unsigned int ROOT_INDEX_IN_TICK = 0xFFFFFFFFU;

// The reference score engine, instantiated with the node's deployed ADDITION parameters
using AntMinerT = score_addition::Miner<14, 8, 256, 256, 256, 256, 67000>;

static std::atomic<char> state(0);

#ifdef _MSC_VER
static BOOL WINAPI ctrlCHandlerRoutine(DWORD dwCtrlType)
{
    if (!state)
    {
        state = 1;
    }
    else
    {
        std::exit(1);
    }
    return TRUE;
}
#else
static void ctrlCHandlerRoutine(int signum)
{
    if (!state)
    {
        state = 1;
    }
    else
    {
        std::exit(1);
    }
}
#endif

static void consoleCtrlHandler()
{
#ifdef _MSC_VER
    SetConsoleCtrlHandler(ctrlCHandlerRoutine, TRUE);
#else
    signal(SIGINT, ctrlCHandlerRoutine);
#endif
}

static char* nodeIp = NULL;
static int nodePort = 0;

static int waitForResponse(ServerSocket& sock, unsigned char wantedType, char* payload, unsigned int payloadCapacity)
{
    static char scratch[1024 * 1024];
    for (int attempt = 0; attempt < 64; attempt++)
    {
        RequestResponseHeader header;
        if (!sock.receiveData((char*)&header, sizeof(header)))
        {
            return -1;
        }
        unsigned int remaining = header.size() - sizeof(header);
        if (header.type() == wantedType)
        {
            if (remaining > payloadCapacity)
            {
                return -1;
            }
            if (remaining > 0 && !sock.receiveData(payload, remaining))
            {
                return -1;
            }
            return (int)remaining;
        }
        // Drain and discard.
        while (remaining > 0)
        {
            unsigned int chunk = remaining < sizeof(scratch) ? remaining : (unsigned int)sizeof(scratch);
            if (!sock.receiveData(scratch, chunk))
            {
                return -1;
            }
            remaining -= chunk;
        }
    }
    return -1;
}

static bool sendRequest(ServerSocket& sock, unsigned char type, const void* payload, unsigned int payloadSize)
{
    struct
    {
        RequestResponseHeader header;
        char payload[128];
    } packet;
    packet.header.setSize(sizeof(RequestResponseHeader) + payloadSize);
    packet.header.randomizeDejavu();
    packet.header.setType(type);
    if (payloadSize > 0)
    {
        memcpy(packet.payload, payload, payloadSize);
    }
    return sock.sendData((char*)&packet, sizeof(RequestResponseHeader) + payloadSize);
}

static bool queryCurrentTickInfo(ServerSocket& sock, RespondCurrentTickInfo& out)
{
    if (!sendRequest(sock, REQUEST_CURRENT_TICK_INFO, NULL, 0))
    {
        return false;
    }
    return waitForResponse(sock, RESPOND_CURRENT_TICK_INFO, (char*)&out, sizeof(out)) == (int)sizeof(out);
}

static bool queryEpochContext(ServerSocket& sock, RespondAntEpochContext& out)
{
    if (!sendRequest(sock, REQUEST_ANT_EPOCH_CONTEXT, NULL, 0))
    {
        return false;
    }
    return waitForResponse(sock, RESPOND_ANT_EPOCH_CONTEXT, (char*)&out, sizeof(out)) == (int)sizeof(out);
}

// Derive the anchor digest for anchorTick from standard messages: fetch the tick's quorum votes
// (REQUEST_QUORUM_TICK), majority-pick the voted transactionDigest, and hash
// K12(anchorTick || transactionDigest) - byte-for-byte the node's definition. Empty ticks need no
// special case: their votes carry a zero transactionDigest, matching the node.
// Returns 1 with anchorDigest filled, 0 when no votes came back (retry later), -1 on network failure.
static int fetchAnchorDigest(ServerSocket& sock, unsigned int anchorTick, unsigned char anchorDigest[32])
{
    RequestedQuorumTick request;
    memset(&request, 0, sizeof(request));
    request.tick = anchorTick;
    // A set bit SKIPS that computor's vote: request only the first 16 votes, plenty for a majority.
    memset(request.voteFlags, 0xFF, sizeof(request.voteFlags));
    request.voteFlags[0] = 0;
    request.voteFlags[1] = 0;
    if (!sendRequest(sock, REQUEST_QUORUM_TICK, &request, sizeof(request)))
    {
        return -1;
    }

    unsigned char votedDigests[16][32];
    unsigned int voteCount = 0;
    for (int attempt = 0; attempt < 64; attempt++)
    {
        RequestResponseHeader header;
        if (!sock.receiveData((char*)&header, sizeof(header)))
        {
            return -1;
        }
        unsigned int remaining = header.size() - sizeof(header);
        if (header.type() == END_RESPONSE && remaining == 0)
        {
            break;
        }
        if (header.type() == BROADCAST_TICK && remaining == sizeof(TickVote) && voteCount < 16)
        {
            TickVote vote;
            if (!sock.receiveData((char*)&vote, sizeof(vote)))
            {
                return -1;
            }
            if (vote.tick == anchorTick)
            {
                memcpy(votedDigests[voteCount], vote.transactionDigest, 32);
                voteCount++;
            }
            continue;
        }
        // Drain and discard other traffic.
        char scratch[4096];
        while (remaining > 0)
        {
            unsigned int chunk = remaining < sizeof(scratch) ? remaining : (unsigned int)sizeof(scratch);
            if (!sock.receiveData(scratch, chunk))
            {
                return -1;
            }
            remaining -= chunk;
        }
    }
    if (voteCount == 0)
    {
        return 0;
    }

    // Majority transactionDigest among the returned votes (guards against a stray misaligned vote).
    unsigned int bestIdx = 0;
    unsigned int bestCount = 0;
    for (unsigned int i = 0; i < voteCount; i++)
    {
        unsigned int count = 0;
        for (unsigned int j = 0; j < voteCount; j++)
        {
            if (memcmp(votedDigests[i], votedDigests[j], 32) == 0)
            {
                count++;
            }
        }
        if (count > bestCount)
        {
            bestCount = count;
            bestIdx = i;
        }
    }

    unsigned char input[36];
    memcpy(input, &anchorTick, 4);
    memcpy(input + 4, votedDigests[bestIdx], 32);
    KangarooTwelve(input, 36, anchorDigest, 32);
    return 1;
}

// One page of the mineable-parents listing starting at fromIndex.
// Returns false on network failure; nextIndex is 0 when there are no more records.
static bool queryMineableParents(ServerSocket& sock, unsigned int fromIndex, std::vector<AntMineableParent>& outEntries, unsigned int& nextIndex)
{
    RequestAntMineableParents request;
    request.fromIndex = fromIndex;
    if (!sendRequest(sock, REQUEST_ANT_MINEABLE_PARENTS, &request, sizeof(request)))
    {
        return false;
    }
    char buffer[sizeof(RespondAntMineableParentsHeader) + 64 * sizeof(AntMineableParent)];
    const int received = waitForResponse(sock, RESPOND_ANT_MINEABLE_PARENTS, buffer, sizeof(buffer));
    if (received < (int)sizeof(RespondAntMineableParentsHeader))
    {
        return false;
    }
    const RespondAntMineableParentsHeader* header = (const RespondAntMineableParentsHeader*)buffer;
    if (header->itemSize != sizeof(AntMineableParent))
    {
        printf("Mineable-parents item size mismatch (node %u, miner %u) - wire structs out of sync!\n",
            header->itemSize, (unsigned int)sizeof(AntMineableParent));
        return false;
    }
    const AntMineableParent* entries = (const AntMineableParent*)(buffer + sizeof(RespondAntMineableParentsHeader));
    for (unsigned int i = 0; i < header->count; i++)
    {
        outEntries.push_back(entries[i]);
    }
    nextIndex = header->nextIndex;
    return true;
}

// One node of this miner's own tree (isolated per-identity trees)
struct OwnNode
{
    unsigned char nonce[32];
    unsigned int score;
    unsigned int anchorTick;                // tick number the grind was anchored to
    unsigned int depth;                     // 1 for root children
    unsigned int parentTickOffset;          // this node's parentRef
    unsigned int parentSolutionIndexInTick;
    bool refKnown;                          // selfRef learned from the node's mineable-parents listing
    unsigned int resolveAttempts;           // resolve cycles seen while still unresolved (mismatch detector)
    unsigned int selfTickOffset;
    unsigned int selfSolutionIndexInTick;
    AntMinerT::ANN ann;                     // this node's evolved ANN (bestANN at grind time)
};

// Local sibling floor, mirroring the node's rule: under the same parent, the child must
// strictly beat every sibling anchored more than N ticks earlier; siblings within N coexist.
// Only our own submissions matter (isolated trees).
static unsigned int localSiblingFloor(const std::vector<OwnNode>& nodes,
    unsigned int parentTickOffset, unsigned int parentSolutionIndexInTick,
    unsigned int childAnchorTick, unsigned int freshnessWindow)
{
    if (childAnchorTick <= freshnessWindow)
    {
        return 0;
    }
    const unsigned int boundary = childAnchorTick - freshnessWindow;
    unsigned int floor = 0;
    for (const OwnNode& node : nodes)
    {
        if (node.parentTickOffset == parentTickOffset
            && node.parentSolutionIndexInTick == parentSolutionIndexInTick
            && node.anchorTick < boundary
            && node.score > floor)
        {
            floor = node.score;
        }
    }
    return floor;
}

// Submit one ant solution as a BroadcastMessage whose decrypted gammingKey[0] selects
// MESSAGE_TYPE_ANT_SOLUTION
static bool submitAntSolution(ServerSocket& sock,
    const unsigned char* signingSubseed, const unsigned char* signingPrivateKey, const unsigned char* signingPublicKey,
    const unsigned char* computorPublicKey,
    unsigned int parentTickOffset, unsigned int parentSolutionIndexInTick,
    unsigned int anchorTick, const unsigned char* nonce)
{
    struct
    {
        RequestResponseHeader header;
        Message message;
        unsigned char payload[44];
        unsigned char signature[64];
    } packet;

    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_MESSAGE);

    memcpy(packet.message.sourcePublicKey, signingPublicKey, 32);
    memcpy(packet.message.destinationPublicKey, computorPublicKey, 32);

    unsigned char sharedKeyAndGammingNonce[64];
    memset(sharedKeyAndGammingNonce, 0, 32);
    if (memcmp(computorPublicKey, signingPublicKey, 32) == 0)
    {
        getSharedKey(signingPrivateKey, computorPublicKey, sharedKeyAndGammingNonce);
    }
    unsigned char gammingKey[32];
    do
    {
        _rdrand64_step((unsigned long long*)&packet.message.gammingNonce[0]);
        _rdrand64_step((unsigned long long*)&packet.message.gammingNonce[8]);
        _rdrand64_step((unsigned long long*)&packet.message.gammingNonce[16]);
        _rdrand64_step((unsigned long long*)&packet.message.gammingNonce[24]);
        memcpy(&sharedKeyAndGammingNonce[32], packet.message.gammingNonce, 32);
        KangarooTwelve(sharedKeyAndGammingNonce, 64, gammingKey, 32);
    } while (gammingKey[0] != MESSAGE_TYPE_ANT_SOLUTION);

    unsigned char plain[44];
    memcpy(plain, &parentTickOffset, 4);
    memcpy(plain + 4, &parentSolutionIndexInTick, 4);
    memcpy(plain + 8, &anchorTick, 4);
    memcpy(plain + 12, nonce, 32);

    unsigned char gamma[sizeof(plain)];
    KangarooTwelve(gammingKey, 32, gamma, sizeof(gamma));
    for (unsigned int i = 0; i < sizeof(plain); i++)
    {
        packet.payload[i] = plain[i] ^ gamma[i];
    }

    unsigned char digest[32];
    KangarooTwelve(
        (unsigned char*)&packet + sizeof(RequestResponseHeader),
        sizeof(packet) - sizeof(RequestResponseHeader) - 64,
        digest,
        32);
    sign(signingSubseed, signingPublicKey, digest, packet.signature);

    return sock.sendData((char*)&packet, sizeof(packet));
}

// Shared grind job: what the workers evolve against. The coordinator republishes it when the
// anchor tick advances, a better parent resolves, or the threshold changes. Workers snapshot
// it per nonce; a result stays valid even if the job moved on (freshness allows publishing
// within N ticks of its anchor), so nothing is ever cancelled.
struct GrindJob
{
    AntMinerT::ANN parentAnn;
    unsigned int parentTickOffset;
    unsigned int parentSolutionIndexInTick;
    unsigned int parentScore;
    // 0 for a ROOT parent
    unsigned int parentDepth;
    unsigned int anchorTick;
    unsigned char anchorDigest[32];
    unsigned int threshold;
    bool valid;
};
static GrindJob gJob;
static std::mutex gJobMutex;

// A solution that cleared threshold and parent score on a worker; the coordinator applies the
// sibling-floor gate and submits.
struct GrindResult
{
    unsigned char nonce[32];
    unsigned int score;
    unsigned int anchorTick;
    unsigned int parentTickOffset;
    unsigned int parentSolutionIndexInTick;
    unsigned int parentScore;
    unsigned int parentDepth;
    AntMinerT::ANN ann;
};
static std::vector<GrindResult> gResults;
static std::mutex gResultsMutex;
static std::atomic<unsigned long long> gIterations(0);

// Worker: pure compute, never touches the network. Own engine, shared read-only pool.
static void grindWorker(const unsigned char* pool, const unsigned char* computorPublicKey)
{
    auto miner = std::make_unique<AntMinerT>();
    miner->setPool(pool);
    miner->generateTrainingSet();

    unsigned char pubkey[32];
    memcpy(pubkey, computorPublicKey, 32);

    while (!state)
    {
        GrindJob job;
        {
            std::lock_guard<std::mutex> guard(gJobMutex);
            job = gJob;
        }
        if (!job.valid)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        unsigned char nonce[32];
        _rdrand64_step((unsigned long long*)&nonce[0]);
        _rdrand64_step((unsigned long long*)&nonce[8]);
        _rdrand64_step((unsigned long long*)&nonce[16]);
        _rdrand64_step((unsigned long long*)&nonce[24]);
        const unsigned int score = miner->computeScoreFromParent(job.parentAnn, pubkey, nonce, job.anchorDigest);
        gIterations++;

        if (score >= job.threshold && score > job.parentScore)
        {
            GrindResult result;
            memcpy(result.nonce, nonce, 32);
            result.score = score;
            result.anchorTick = job.anchorTick;
            result.parentTickOffset = job.parentTickOffset;
            result.parentSolutionIndexInTick = job.parentSolutionIndexInTick;
            result.parentScore = job.parentScore;
            result.parentDepth = job.parentDepth;
            memcpy(&result.ann, &miner->bestANN, sizeof(AntMinerT::ANN));
            std::lock_guard<std::mutex> guard(gResultsMutex);
            gResults.push_back(result);
        }
    }
}

int main(int argc, char* argv[])
{
    if (argc < 5 || argc > 7)
    {
        printf("Usage: AntMiner [Node IP] [Node Port] [MiningID] [Signing Seed] [Threads] [-dummy]\n");
        printf("  Threads: grinder thread count; default = hardware cores - 1\n");
        printf("  -dummy:  no scoring; submit random solutions (mixed valid-shaped, garbage-parent,\n");
        printf("           stale-anchor) to exercise the node's queue filter and reject paths\n");
        return 1;
    }
    bool dummyMode = false;
    int requestedThreads = 0;
    for (int i = 5; i < argc; i++)
    {
        if (strcmp(argv[i], "-dummy") == 0)
        {
            dummyMode = true;
        }
        else
        {
            requestedThreads = std::atoi(argv[i]);
        }
    }
    nodeIp = argv[1];
    nodePort = std::atoi(argv[2]);
    char* miningID = argv[3];
    char* signingSeed = argv[4];

    consoleCtrlHandler();

    unsigned char computorPublicKey[32];
    getPublicKeyFromIdentity(miningID, computorPublicKey);

    unsigned char signingSubseed[32];
    unsigned char signingPrivateKey[32];
    unsigned char signingPublicKey[32];
    getSubseedFromSeed((unsigned char*)signingSeed, signingSubseed);
    getPrivateKeyFromSubSeed(signingSubseed, signingPrivateKey);
    getPublicKeyFromPrivateKey(signingPrivateKey, signingPublicKey);

    printf("AntMiner is launched. Connecting to %s:%d, mining for %s\n", nodeIp, nodePort, miningID);

    ServerSocket sock;
    if (!sock.establishConnection(nodeIp, nodePort))
    {
        return 1;
    }

    RespondCurrentTickInfo tickInfo;
    if (!queryCurrentTickInfo(sock, tickInfo))
    {
        printf("Failed to query current tick info.\n");
        return 1;
    }
    printf("Epoch %u, tick %u (initial %u)\n", tickInfo.epoch, tickInfo.tick, tickInfo.initialTick);

    RespondAntEpochContext epochContext;
    if (!queryEpochContext(sock, epochContext))
    {
        printf("Failed to query ant epoch context.\n");
        return 1;
    }
    bool digestIsZero = true;
    for (int i = 0; i < 32; i++)
    {
        if (epochContext.spectrumDigest[i] != 0)
        {
            digestIsZero = false;
        }
    }
    if (digestIsZero)
    {
        printf("Node returned a zero spectrum digest - ant colony not initialized on the node?\n");
        return 1;
    }
    printf("Ant epoch context: threshold %u, freshness window %u ticks, %u solutions so far\n",
        epochContext.threshold, epochContext.freshnessWindow, epochContext.solutionCount);

    // Full pipeline start (skipped entirely in dummy mode - no score engine at all):
    // ONE shared read-only pool from the epoch digest (fixed for the whole epoch on the
    // node too), then this identity's root, then the grinder threads.
    std::vector<unsigned char> sharedPool;
    std::unique_ptr<AntMinerT> miner;
    AntMinerT::ANN rootAnn;
    memset(&rootAnn, 0, sizeof(rootAnn));
    memset(&gJob, 0, sizeof(gJob));
    std::vector<std::thread> workers;
    if (dummyMode)
    {
        printf("Dummy mode: submitting random solutions, no scoring.\n");
    }
    else
    {
        sharedPool.resize(POOL_VEC_PADDING_SIZE);
        generateRandom2Pool(epochContext.spectrumDigest, sharedPool.data());
        miner = std::make_unique<AntMinerT>();
        miner->setPool(sharedPool.data());
        rootAnn = miner->deriveRootANN(computorPublicKey, epochContext.spectrumDigest);
        printf("Per-identity root derived.\n");

        unsigned int threadCount = std::thread::hardware_concurrency();
        threadCount = (threadCount > 1) ? (threadCount - 1) : 1;
        if (requestedThreads > 0)
        {
            threadCount = (unsigned int)requestedThreads;
        }
        for (unsigned int t = 0; t < threadCount; t++)
        {
            workers.emplace_back(grindWorker, sharedPool.data(), computorPublicKey);
        }
        printf("%u grinder threads started.\n", threadCount);
    }

    std::vector<OwnNode> ownNodes;
    // Latest mineable-parents listing (refreshed each resolve cycle); dummy mode picks
    // real parent refs from it.
    std::vector<AntMineableParent> listing;
    unsigned long long submitted = 0;
    auto lastResolveTime = std::chrono::steady_clock::now();

    // Anchor cache: refetched from the tick's quorum votes only when the tick advances.
    unsigned int cachedAnchorTick = 0xFFFFFFFFU;
    unsigned char cachedAnchorDigest[32];

    while (!state)
    {
        // Parent selection: the best own node whose selfRef is known (deepest frontier),
        // or ROOT when none is resolved yet.
        // Pool miner can tune here to select the parent that maximize their miner score
        const OwnNode* parentNode = NULL;
        for (const OwnNode& node : ownNodes)
        {
            if (node.refKnown && (parentNode == NULL || node.score > parentNode->score))
            {
                parentNode = &node;
            }
        }
        const unsigned int parentTickOffset = parentNode ? parentNode->selfTickOffset : ROOT_TICK_OFFSET;
        const unsigned int parentSolutionIndexInTick = parentNode ? parentNode->selfSolutionIndexInTick : ROOT_INDEX_IN_TICK;
        const unsigned int parentScore = parentNode ? parentNode->score : 0U;
        const AntMinerT::ANN& parentAnn = parentNode ? parentNode->ann : rootAnn;

        // Anchor-first: the anchor digest is part of the child RNG seed, so the anchor is chosen
        // BEFORE grinding. Anchor at the latest COMPLETED tick (current - 1): its quorum votes are
        // stored and every node's anchor ring already holds it. The digest is derived from standard
        // messages only and refetched when the tick advances, so the anchor stays close to the
        // current tick, well within the freshness window.
        if (!queryCurrentTickInfo(sock, tickInfo))
        {
            printf("Tick info query failed, reconnecting...\n");
            sock.closeConnection();
            while (!state && !sock.establishConnection(nodeIp, nodePort))
            {
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
            continue;
        }
        if (tickInfo.tick <= tickInfo.initialTick)
        {
            // No completed tick in this epoch yet - previous-epoch anchors are not in the ring.
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        const unsigned int anchorTick = tickInfo.tick - 1U;
        if (anchorTick != cachedAnchorTick)
        {
            const int fetched = fetchAnchorDigest(sock, anchorTick, cachedAnchorDigest);
            if (fetched < 0)
            {
                printf("Anchor fetch failed, reconnecting...\n");
                sock.closeConnection();
                while (!state && !sock.establishConnection(nodeIp, nodePort))
                {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
                continue;
            }
            if (fetched == 0)
            {
                // Votes not available yet - retry next iteration.
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            cachedAnchorTick = anchorTick;
            // Same 8-byte prefix the node prints on F3 ("AntColony: anchor tick T digest=...");
            // compare to spot an anchor-digest divergence at a specific tick.
            unsigned long long digestPrefix = 0;
            memcpy(&digestPrefix, cachedAnchorDigest, 8);
            printf("Anchor tick %u digest=%llu\n", anchorTick, digestPrefix);
        }

        if (dummyMode)
        {
            // No scoring: fabricate one submission per loop pass. Mix of parent picks so the
            // node's queue filter, publish gate, and reject stats all see traffic:
            // real listed parent / ROOT / garbage ref, and occasionally a stale anchor.
            unsigned int dummyParentTickOffset = ROOT_TICK_OFFSET;
            unsigned int dummyParentIndex = ROOT_INDEX_IN_TICK;
            unsigned long long roll = 0;
            _rdrand64_step(&roll);
            const unsigned int pick = (unsigned int)(roll % 100U);
            if (pick < 60U && !listing.empty())
            {
                const AntMineableParent& entry = listing[(roll >> 8) % listing.size()];
                dummyParentTickOffset = entry.parentTickOffset;
                dummyParentIndex = entry.parentSolutionIndexInTick;
            }
            else if (pick >= 80U)
            {
                dummyParentTickOffset = (unsigned int)((roll >> 8) % (tickInfo.tick - tickInfo.initialTick + 1U));
                dummyParentIndex = (unsigned int)((roll >> 40) % 4U);
            }
            unsigned int dummyAnchorTick = cachedAnchorTick;
            unsigned long long anchorRoll = 0;
            _rdrand64_step(&anchorRoll);
            if ((anchorRoll % 10U) == 0U
                && cachedAnchorTick > tickInfo.initialTick + epochContext.freshnessWindow + 20U)
            {
                dummyAnchorTick = cachedAnchorTick - epochContext.freshnessWindow - 10U;
            }
            unsigned char nonce[32];
            _rdrand64_step((unsigned long long*)&nonce[0]);
            _rdrand64_step((unsigned long long*)&nonce[8]);
            _rdrand64_step((unsigned long long*)&nonce[16]);
            _rdrand64_step((unsigned long long*)&nonce[24]);
            if (!submitAntSolution(sock, signingSubseed, signingPrivateKey, signingPublicKey, computorPublicKey,
                dummyParentTickOffset, dummyParentIndex, dummyAnchorTick, nonce))
            {
                printf("Submit failed, reconnecting...\n");
                sock.closeConnection();
                while (!state && !sock.establishConnection(nodeIp, nodePort))
                {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
                continue;
            }
            submitted++;
        }
        else
        {
            // Publish the job for the grinder threads (parent, anchor, or threshold may have changed).
            {
                std::lock_guard<std::mutex> guard(gJobMutex);
                memcpy(&gJob.parentAnn, &parentAnn, sizeof(AntMinerT::ANN));
                gJob.parentTickOffset = parentTickOffset;
                gJob.parentSolutionIndexInTick = parentSolutionIndexInTick;
                gJob.parentScore = parentScore;
                gJob.parentDepth = parentNode ? parentNode->depth : 0U;
                gJob.anchorTick = cachedAnchorTick;
                memcpy(gJob.anchorDigest, cachedAnchorDigest, 32);
                gJob.threshold = epochContext.threshold;
                gJob.valid = true;
            }

            // Drain worker hits: apply the sibling-floor gate, submit, track as own nodes.
            std::vector<GrindResult> results;
            {
                std::lock_guard<std::mutex> guard(gResultsMutex);
                results.swap(gResults);
            }
            bool submitFailed = false;
            for (size_t i = 0; i < results.size(); i++)
            {
                const GrindResult& r = results[i];
                const unsigned int floor = localSiblingFloor(ownNodes, r.parentTickOffset, r.parentSolutionIndexInTick, r.anchorTick, epochContext.freshnessWindow);
                if (r.score <= floor)
                {
                    continue;
                }

                if (!submitAntSolution(sock, signingSubseed, signingPrivateKey, signingPublicKey, computorPublicKey,
                    r.parentTickOffset, r.parentSolutionIndexInTick, r.anchorTick, r.nonce))
                {
                    // Requeue this and the remaining results; they stay valid within the
                    // freshness window and get another chance after the reconnect.
                    std::lock_guard<std::mutex> guard(gResultsMutex);
                    gResults.insert(gResults.end(), results.begin() + i, results.end());
                    submitFailed = true;
                    break;
                }
                submitted++;
                OwnNode node;
                memcpy(node.nonce, r.nonce, 32);
                node.score = r.score;
                node.anchorTick = r.anchorTick;
                node.depth = r.parentDepth + 1U;
                node.parentTickOffset = r.parentTickOffset;
                node.parentSolutionIndexInTick = r.parentSolutionIndexInTick;
                node.refKnown = false;
                node.resolveAttempts = 0;
                node.selfTickOffset = 0;
                node.selfSolutionIndexInTick = 0;
                memcpy(&node.ann, &r.ann, sizeof(AntMinerT::ANN));
                ownNodes.push_back(node);
                printf("Submitted: depth %u, score %u (parent score %u, floor %u), anchor %u\n",
                    node.depth, r.score, r.parentScore, floor, r.anchorTick);
            }
            if (submitFailed)
            {
                printf("Submit failed, reconnecting...\n");
                sock.closeConnection();
                while (!state && !sock.establishConnection(nodeIp, nodePort))
                {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
                continue;
            }
        }

        // Periodically resolve our submitted nodes' selfRefs from the node's listing and
        // report tree growth (the proof-of-working readout).
        const auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastResolveTime).count() >= 10)
        {
            lastResolveTime = now;

            std::vector<AntMineableParent> entries;
            unsigned int fromIndex = 0;
            bool queryOk = true;
            do
            {
                unsigned int nextIndex = 0;
                if (!queryMineableParents(sock, fromIndex, entries, nextIndex))
                {
                    queryOk = false;
                    break;
                }
                fromIndex = nextIndex;
            } while (fromIndex != 0);

            if (queryOk)
            {
                listing = entries;
                unsigned int resolved = 0;
                for (OwnNode& node : ownNodes)
                {
                    if (node.refKnown)
                    {
                        resolved++;
                        continue;
                    }
                    // The listing has no identity field; match on (score, anchorTick, depth).
                    // Unambiguous in a low-traffic validation run.
                    for (const AntMineableParent& entry : entries)
                    {
                        if (entry.parentScore == node.score
                            && entry.anchorTick == node.anchorTick
                            && entry.depth == node.depth)
                        {
                            node.refKnown = true;
                            node.selfTickOffset = entry.parentTickOffset;
                            node.selfSolutionIndexInTick = entry.parentSolutionIndexInTick;
                            resolved++;
                            break;
                        }
                    }
                    if (!node.refKnown)
                    {
                        node.resolveAttempts++;
                        if (node.resolveAttempts == 3U)
                        {
                            // The node recomputes the score from (pubkey, parentRef, anchorTick,
                            // nonce); if our score never appears on-chain, the recomputation
                            // disagreed with ours - the anchor digest is the prime suspect.
                            printf("WARNING: solution (score %u, anchor %u) not accepted after %u resolve cycles - possible anchor digest mismatch, compare 'Anchor tick N digest=' with the node's F3 line\n",
                                node.score, node.anchorTick, node.resolveAttempts);
                        }
                    }
                }

                RespondAntEpochContext refreshed;
                if (queryEpochContext(sock, refreshed))
                {
                    epochContext = refreshed;
                }
                printf("| %llu iterations | %llu submitted | %u/%zu accepted+resolved | tree size %u |\n",
                    gIterations.load(), submitted, resolved, ownNodes.size(), epochContext.solutionCount);
            }
            else
            {
                printf("Resolve query failed, reconnecting...\n");
                sock.closeConnection();
                while (!state && !sock.establishConnection(nodeIp, nodePort))
                {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }
        }
        // Coordinator pace: the workers grind continuously; this loop only shuttles jobs,
        // results, and queries.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    for (std::thread& worker : workers)
    {
        worker.join();
    }
    sock.closeConnection();
    printf("AntMiner is shut down. %llu iterations, %llu submitted, %zu own nodes.\n", gIterations.load(), submitted, ownNodes.size());
    return 0;
}
