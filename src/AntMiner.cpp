// AntMiner: ant-colony reference miner.
//
// Validation harness for the core node's ant-colony mining: runs the full pipeline
// (query epoch context, derive the per-identity root, grind children with
// computeScoreFromParent, submit solutions, track its own growing tree), single-threaded,
// no performance tuning
// Usage: AntMiner [Node IP] [Node Port] [MiningID] [Signing Seed]

#include <chrono>
#include <thread>
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
using AntMinerT = score_addition::Miner<14, 8, 256, 256, 256, 256, 74100>;

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

int main(int argc, char* argv[])
{
    if (argc != 5)
    {
        printf("Usage: AntMiner [Node IP] [Node Port] [MiningID] [Signing Seed]\n");
        return 1;
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

    // Full pipeline start: pool from the epoch digest, then this identity's root.
    auto miner = std::make_unique<AntMinerT>();
    miner->initialize(epochContext.spectrumDigest);
    const AntMinerT::ANN rootAnn = miner->deriveRootANN(computorPublicKey, epochContext.spectrumDigest);
    printf("Per-identity root derived.\n");

    std::vector<OwnNode> ownNodes;
    unsigned long long iterations = 0;
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
        // messages only and refetched when the tick advances (one compute takes about a second, so
        // the anchor stays close to the current tick, well within the freshness window).
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

        // Grind one nonce (full scoring, exactly what the node recomputes on commit).
        unsigned char nonce[32];
        _rdrand64_step((unsigned long long*)&nonce[0]);
        _rdrand64_step((unsigned long long*)&nonce[8]);
        _rdrand64_step((unsigned long long*)&nonce[16]);
        _rdrand64_step((unsigned long long*)&nonce[24]);
        const unsigned int score = miner->computeScoreFromParent(parentAnn, computorPublicKey, nonce, cachedAnchorDigest);
        iterations++;

        if (score >= epochContext.threshold && score > parentScore)
        {
            const unsigned int floor = localSiblingFloor(ownNodes, parentTickOffset, parentSolutionIndexInTick, anchorTick, epochContext.freshnessWindow);
            if (score <= floor)
            {
                continue;
            }

            if (submitAntSolution(sock, signingSubseed, signingPrivateKey, signingPublicKey, computorPublicKey,
                parentTickOffset, parentSolutionIndexInTick, anchorTick, nonce))
            {
                submitted++;
                OwnNode node;
                memcpy(node.nonce, nonce, 32);
                node.score = score;
                node.anchorTick = anchorTick;
                node.depth = parentNode ? parentNode->depth + 1U : 1U;
                node.parentTickOffset = parentTickOffset;
                node.parentSolutionIndexInTick = parentSolutionIndexInTick;
                node.refKnown = false;
                node.resolveAttempts = 0;
                node.selfTickOffset = 0;
                node.selfSolutionIndexInTick = 0;
                memcpy(&node.ann, &miner->bestANN, sizeof(AntMinerT::ANN));
                ownNodes.push_back(node);
                printf("Submitted: depth %u, score %u (parent score %u, floor %u), anchor %u\n",
                    node.depth, score, parentScore, floor, anchorTick);
            }
            else
            {
                printf("Submit failed, reconnecting...\n");
                sock.closeConnection();
                while (!state && !sock.establishConnection(nodeIp, nodePort))
                {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
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
                    iterations, submitted, resolved, ownNodes.size(), epochContext.solutionCount);
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
    }

    sock.closeConnection();
    printf("AntMiner is shut down. %llu iterations, %llu submitted, %zu own nodes.\n", iterations, submitted, ownNodes.size());
    return 0;
}
