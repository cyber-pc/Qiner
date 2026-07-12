#pragma once

#include "score_common.h"
#include "K12AndKeyUtil.h"
#include "task_file.h"

#include <cassert>
#include <vector>

// Generic LUT score engine.
// Every neuron holds a trit and computes its next value by looking up a per-neuron table indexed
// by the trits of its neighbour neurons; only the LUT contents change under mutation.
//
// Trit values are {0, 1, 2} where 0 and 1 are the two decided states and 2 means UNKNOWN.
//
// Scoring streams a sliding window of a time-ordered sequence into the input neurons at the
// network's own pace (gated by a signal neuron), then settles until the signal goes UNKNOWN
// (ready) before reading one output neuron. A window that cannot finish inside the tick budget
// times out and fails the whole ANN.
namespace score_generic_lut
{

static constexpr unsigned long long NUMBER_OF_INPUT_NEURONS = 14;
static constexpr unsigned long long NUMBER_OF_OUTPUT_NEURONS = 1;
static constexpr unsigned long long POPULATION_THRESHOLD = 256;
static constexpr unsigned long long NUMBER_OF_NEIGHBORS = 3;
static constexpr unsigned long long NUMBER_OF_MUTATIONS = 100;
static constexpr unsigned long long MAX_NUMBER_OF_TICKS = 256;

// Max LUT entries one mutation step may use (miner-chosen L from nonce[])
static constexpr unsigned int MAX_LUT_ENTRIES_PER_STEP = 10;

// Task relate params. 
// TODO: match this when the task file is released
static constexpr unsigned long long SEQUENCE_LENGTH = 128;              // T, total samples
static constexpr unsigned long long WINDOW_WIDTH = SEQUENCE_LENGTH / 2; // W

// Placeholder acceptance threshold; the real threshold is epoch config.
// TODO: remove this, we use best score
static constexpr unsigned int SOLUTION_THRESHOLD = (unsigned int)((WINDOW_WIDTH - 1) * 4 / 5);

template <
    unsigned long long numberOfInputNeurons,
    unsigned long long numberOfOutputNeurons,
    unsigned long long sequenceLength,
    unsigned long long windowWidth,
    unsigned long long maxNumberOfTicks,
    unsigned long long numberOfNeighbors,  // LUT fan-in (neighbours read per neuron)
    unsigned long long populationThreshold,   // P
    unsigned long long numberOfMutations,     // S
    unsigned int solutionThreshold>
struct Miner
{
    static constexpr unsigned long long maxNumberOfNeurons = populationThreshold;
    static constexpr unsigned long long numberOfWindows = sequenceLength - windowWidth;

    static constexpr unsigned long long topoBlockSize =
        (numberOfInputNeurons + numberOfOutputNeurons + 1 + numberOfNeighbors) * sizeof(uint32_t);
    static constexpr unsigned long long dataBlockSize =
        sequenceLength * (((numberOfInputNeurons + task_file::TRITS_PER_BYTE - 1) / task_file::TRITS_PER_BYTE)
                          + ((numberOfOutputNeurons + task_file::TRITS_PER_BYTE - 1) / task_file::TRITS_PER_BYTE));

    // Undecided trit (the third value); the two decided states are 0 and 1.
    static constexpr unsigned char TRIT_UNKNOWN = 2;

    // Any timed-out window fails the whole ANN; this stands in for its infinite score.
    static constexpr unsigned int INFINITE_ERROR = 0xFFFFFFFFU;

    // 3 trit inputs, 3^3 = 27 lines per LUT (one output trit per neighbour-trit combination).
    static constexpr unsigned long long lutSize = 27;

    static_assert(
        numberOfNeighbors == 3,
        "the LUT index is hardcoded for 3 neighbours");
    static_assert(
        populationThreshold > numberOfInputNeurons + numberOfOutputNeurons + 1,
        "populationThreshold must leave room for the evolution neurons and the signal neuron");
    static_assert(
        (populationThreshold & (populationThreshold - 1)) == 0,
        "populationThreshold must be a power of 2");
    static_assert(
        windowWidth >= 2 && windowWidth < sequenceLength,
        "windowWidth must be at least 2 and leave room for the target after the window");

    std::vector<unsigned char> poolVec;

    // Init the random2 pool from the mining seed, then load the task file (topology + data).
    // Returns false if the task file cannot be loaded or validated
    bool initialize(unsigned char* miningSeed, const char* taskFilePath)
    {
        poolVec.resize(POOL_VEC_PADDING_SIZE);
        generateRandom2Pool(miningSeed, poolVec.data());

        return loadTaskData(taskFilePath);
    }

    // Load the unified task file. Returns false on any mismatch.
    bool loadTaskData(const char* taskFilePath)
    {
        task_file::TaskFileHeader header;
        if (!task_file::readTaskFileHeader(taskFilePath, &header))
        {
            return false;
        }
        if (header.magic != task_file::MAGIC ||
            header.version != task_file::VERSION ||
            header.numInputTrits != numberOfInputNeurons ||
            header.numOutputTrits != numberOfOutputNeurons ||
            header.numPairs != sequenceLength ||
            header.population != populationThreshold ||
            header.numNeighbors != numberOfNeighbors)
        {
            return false;
        }

        unsigned char hash[task_file::DATA_HASH_SIZE];

        // Topology
        if (!task_file::readTaskFileBlock(taskFilePath, sizeof(task_file::TaskFileHeader), topoBlockBuf, topoBlockSize))
        {
            return false;
        }
        KangarooTwelve(topoBlockBuf, (unsigned int)topoBlockSize, hash, task_file::DATA_HASH_SIZE);
        if (memcmp(hash, header.topologyHash, task_file::DATA_HASH_SIZE) != 0)
        {
            return false;
        }
        task_file::parseTopologyBlock(topoBlockBuf, numberOfInputNeurons, numberOfOutputNeurons, numberOfNeighbors,
                                      inputNeuronIndices, outputNeuronIndices, &signalNeuronIndex, neighborOffsets);
        if (!validateTopology())
        {
            return false;
        }

        // Training data read, verify its hash, unpack into inputs/outputs.
        if (!task_file::readTaskFileBlock(taskFilePath, sizeof(task_file::TaskFileHeader) + topoBlockSize, dataBlockBuf, dataBlockSize))
        {
            return false;
        }
        KangarooTwelve(dataBlockBuf, (unsigned int)dataBlockSize, hash, task_file::DATA_HASH_SIZE);
        if (memcmp(hash, header.dataHash, task_file::DATA_HASH_SIZE) != 0)
        {
            return false;
        }
        if (!task_file::unpackDataBlock(numberOfInputNeurons, numberOfOutputNeurons, sequenceLength, dataBlockBuf, &inputs[0][0], &outputs[0][0]))
        {
            return false;
        }

        deriveNeuronRoles();
        return true;
    }

    // Validate the loaded topology
    bool validateTopology()
    {
        for (unsigned long long i = 0; i < numberOfInputNeurons; ++i)
        {
            if (inputNeuronIndices[i] >= populationThreshold)
            {
                return false;
            }
        }
        for (unsigned long long i = 0; i < numberOfOutputNeurons; ++i)
        {
            if (outputNeuronIndices[i] >= populationThreshold)
            {
                return false;
            }
        }
        if (signalNeuronIndex >= populationThreshold)
        {
            return false;
        }

        // input, output and signal must be mutually distinct (one role per neuron).
        bool seen[populationThreshold] = {};
        for (unsigned long long i = 0; i < numberOfInputNeurons; ++i)
        {
            if (seen[inputNeuronIndices[i]])
            {
                return false;
            }
            seen[inputNeuronIndices[i]] = true;
        }
        for (unsigned long long i = 0; i < numberOfOutputNeurons; ++i)
        {
            if (seen[outputNeuronIndices[i]])
            {
                return false;
            }
            seen[outputNeuronIndices[i]] = true;
        }
        if (seen[signalNeuronIndex])
        {
            return false;
        }
        return true;
    }

    // Derive neuron types (input/output/evolution) and the updated-neuron list from the placement.
    void deriveNeuronRoles()
    {
        for (unsigned long long i = 0; i < populationThreshold; ++i)
        {
            neuronTypes[i] = Neuron::kEvolution;
        }
        for (unsigned long long i = 0; i < numberOfInputNeurons; ++i)
        {
            neuronTypes[inputNeuronIndices[i]] = Neuron::kInput;
        }
        for (unsigned long long i = 0; i < numberOfOutputNeurons; ++i)
        {
            neuronTypes[outputNeuronIndices[i]] = Neuron::kOutput;
        }
        // The signal neuron stays kEvolution; only its index is tracked.

        numberOfUpdatedNeurons = 0;
        for (unsigned long long i = 0; i < populationThreshold; ++i)
        {
            if (neuronTypes[i] != Neuron::kInput)
            {
                updatedNeuronIndices[numberOfUpdatedNeurons] = i;
                numberOfUpdatedNeurons++;
            }
        }
    }

    // SequenceLength samples, each numberOfInputNeurons input trits and
    // numberOfOutputNeurons expected-output trits. 
    // Data is {0, 1}; trit 2 stays the UNKNOWN marker.
    unsigned char inputs[sequenceLength][numberOfInputNeurons];
    unsigned char outputs[sequenceLength][numberOfOutputNeurons];

    // Buffers
    unsigned char topoBlockBuf[topoBlockSize];
    unsigned char dataBlockBuf[dataBlockSize];

    // Data for running the ANN
    struct Neuron
    {
        enum Type
        {
            kInput,
            kOutput,
            kEvolution,
        };
        Type type;
        unsigned char value; // trit in {0, 1, 2}
    };

    // Data for roll back, mutation will change LUT output contents
    struct ANN
    {
        Neuron neurons[maxNumberOfNeurons];
        unsigned char lut[maxNumberOfNeurons * lutSize];
    };
    ANN bestANN;
    ANN currentANN;
    // Snapshot for the one-step rollback in the anti-attractor walk.
    ANN prevANN;

    struct InitValue
    {
        unsigned char lutInit[maxNumberOfNeurons * lutSize]; // one byte per LUT line, taken mod 3
        unsigned long long mutationSeed[numberOfMutations * MAX_LUT_ENTRIES_PER_STEP];
    } initValue;


    unsigned char nextNeuronValue[maxNumberOfNeurons];

    // Topology loaded from the task file (uint32, matching the file layout)
    uint32_t neighborOffsets[numberOfNeighbors];

    uint32_t inputNeuronIndices[numberOfInputNeurons];
    uint32_t outputNeuronIndices[numberOfOutputNeurons];

    // One evolution neuron drives the feed handshake; it is computed and mutated like any other
    // evolution neuron, its value is only additionally read for flow control.
    uint32_t signalNeuronIndex;

    // Epoch-fixed neuron placement (input/output/evolution), derived from the loaded topology.
    Neuron::Type neuronTypes[maxNumberOfNeurons];

    // Indices of all non-input neurons (output + evolution), the only ones whose LUT is used
    // and the only ones a mutation may touch. Filled in deriveNeuronRoles().
    unsigned long long updatedNeuronIndices[maxNumberOfNeurons];
    unsigned long long numberOfUpdatedNeurons;

    // Inference step, every non-input neuron looks up its next trit from the trits of its neighbours
    void processTick()
    {
        const unsigned long long population = populationThreshold;
        Neuron* neurons = currentANN.neurons;

        for (unsigned long long n = 0; n < population; ++n)
        {
            if (Neuron::kInput == neurons[n].type)
            {
                nextNeuronValue[n] = neurons[n].value; // inputs are driven externally, not here
                continue;
            }

            // Ring neighbours (n + offset) mod P, then a base-3 index over their trits t0 + 3*t1 + 9*t2.
            const unsigned long long t0 = neurons[(n + neighborOffsets[0]) % populationThreshold].value;
            const unsigned long long t1 = neurons[(n + neighborOffsets[1]) % populationThreshold].value;
            const unsigned long long t2 = neurons[(n + neighborOffsets[2]) % populationThreshold].value;
            nextNeuronValue[n] = currentANN.lut[n * lutSize + (t0 + 3 * t1 + 9 * t2)];
        }

        // Commit the new values
        for (unsigned long long n = 0; n < population; ++n)
        {
            if (Neuron::kInput != neurons[n].type)
            {
                neurons[n].value = nextNeuronValue[n];
            }
        }
    }

    // Windowed self-clocked score matching the reference score(). Returns the total error count,
    // or INFINITE_ERROR if any window times out (an ANN has failed).
    unsigned int score()
    {
        unsigned int numberOfFailures = 0;

        Neuron* neurons = currentANN.neurons;

        for (unsigned long long trainingEntryIndex = 0; trainingEntryIndex < numberOfWindows; ++trainingEntryIndex)
        {
            unsigned long long feedCounter = 0;

            // Blank slate: every neuron UNKNOWN, so the signal starts ready.
            for (unsigned long long n = 0; n < populationThreshold; ++n)
            {
                neurons[n].value = TRIT_UNKNOWN;
            }

            unsigned long long tick;
            for (tick = 0; tick < maxNumberOfTicks; tick++)
            {
                if (neurons[signalNeuronIndex].value == TRIT_UNKNOWN)
                {
                    // Signal ready. Once the whole window is in, the output neuron holds the
                    // prediction - stop before running another tick; otherwise drive the next sample.
                    if (feedCounter >= windowWidth)
                    {
                        break;
                    }
                    for (unsigned long long i = 0; i < numberOfInputNeurons; ++i)
                    {
                        neurons[inputNeuronIndices[i]].value = inputs[trainingEntryIndex + feedCounter][i];
                    }
                    feedCounter++;
                }
                else
                {
                    // Signal not ready, drive UNKNOWN and keep computing.
                    for (unsigned long long i = 0; i < numberOfInputNeurons; ++i)
                    {
                        neurons[inputNeuronIndices[i]].value = TRIT_UNKNOWN;
                    }
                }

                processTick();
            }

            // A single timed-out window fails the whole ANN; the remaining windows cannot change
            // that, so abandon this candidate immediately.
            if (tick == maxNumberOfTicks)
            {
                return INFINITE_ERROR;
            }

            // Any mismatch is a failure - a wrong decided trit and an UNKNOWN count the same.
            const unsigned char predicted = neurons[outputNeuronIndices[0]].value;
            const unsigned char expected = outputs[trainingEntryIndex + feedCounter][0];
            if (predicted != expected)
            {
                numberOfFailures++;
            }
        }

        return numberOfFailures;
    }

    // Rewrite a single LUT line of a single updated (non-input) neuron to a different trit.
    //  bit 0 selects the change, and the high bits select LUT-line to change
    void mutate(unsigned long long mutationSeed)
    {
        // bit 0: which of the two other trits to move to (always a change)
        const unsigned long long delta = mutationSeed & 1ULL;

        // bits 1..63: which LUT line
        const unsigned long long totalLines = numberOfUpdatedNeurons * lutSize;
        const unsigned long long flatIdx = (mutationSeed >> 1) % totalLines;
        const unsigned long long neuronIdx = updatedNeuronIndices[flatIdx / lutSize];
        const unsigned long long line = flatIdx % lutSize;

        const unsigned char oldTrit = currentANN.lut[neuronIdx * lutSize + line];
        const unsigned char newTrit = (unsigned char)((oldTrit + 1 + delta) % 3);
        currentANN.lut[neuronIdx * lutSize + line] = newTrit;
    }

    unsigned int initializeANN(unsigned char* publicKey, unsigned char* nonce)
    {
        const unsigned long long population = populationThreshold;
        Neuron* neurons = currentANN.neurons;

        // Root LUT comes from the public key
        unsigned char rootHash[32];
        KangarooTwelve(publicKey, 32, rootHash, 32);
        random2(rootHash, poolVec.data(), (unsigned char*)&initValue.lutInit, sizeof(initValue.lutInit));

        // Mutation stream comes from public key + nonce, so different nonces explore different paths
        // from that same root. K, L and the algo bit live in nonce[0..2], excluded so they do not
        // perturb the stream.
        unsigned char searchHash[32];
        unsigned char combined[64];
        memcpy(combined, publicKey, 32);
        memcpy(combined + 32, nonce, 32);
        combined[32] = 0;
        combined[33] = 0;
        combined[34] = 0;
        KangarooTwelve(combined, 64, searchHash, 32);
        random2(searchHash, poolVec.data(), (unsigned char*)&initValue.mutationSeed, sizeof(initValue.mutationSeed));

        // Apply the epoch-fixed neuron placement
        for (unsigned long long i = 0; i < population; ++i)
        {
            neurons[i].type = neuronTypes[i];
            neurons[i].value = TRIT_UNKNOWN;
        }

        // Seed every LUT line with a trit.
        for (unsigned long long n = 0; n < population; ++n)
        {
            for (unsigned long long line = 0; line < lutSize; ++line)
            {
                currentANN.lut[n * lutSize + line] = (unsigned char)(initValue.lutInit[n * lutSize + line] % 3);
            }
        }

        // Error count of the starting ANN.
        return score();
    }

    // Main mining function: N mutation steps with the anti-attractor split
    unsigned int computeScore(unsigned char* publicKey, unsigned char* nonce)
    {
        // Miner knobs from nonce[1..2], do not affect the RNG.
        unsigned int L = nonce[1];
        if (L < 1)
        {
            L = 1;
        }
        if (L > MAX_LUT_ENTRIES_PER_STEP)
        {
            L = MAX_LUT_ENTRIES_PER_STEP;
        }
        unsigned long long K = nonce[2];
        if (K > numberOfMutations)
        {
            K = numberOfMutations;
        }

        unsigned int cur = initializeANN(publicKey, nonce);
        memcpy(&bestANN, &currentANN, sizeof(bestANN));
        unsigned int best = cur;

        for (unsigned long long s = 0; s < numberOfMutations; ++s)
        {
            // Snapshot for the one-step rollback.
            memcpy(&prevANN, &currentANN, sizeof(prevANN));

            // Apply L LUT-entry mutations from this step's fixed seed slot.
            for (unsigned int i = 0; i < L; ++i)
            {
                mutate(initValue.mutationSeed[s * MAX_LUT_ENTRIES_PER_STEP + i]);
            }

            const unsigned int r = score();

            bool accept = false;
            if (s < K)
            {
                // First K steps, keep the mutation if it made the score worse (or equal).
                accept = (r >= cur);
            }
            else
            {
                // Then, keep the mutation if it made the score better (or equal).
                accept = (r <= cur);
            }

            if (accept)
            {
                cur = r;
            }
            else
            {
                // Roll back one step (to the previous position, NOT to the best).
                memcpy(&currentANN, &prevANN, sizeof(currentANN));
            }

            if (cur < best)
            {
                best = cur;
                memcpy(&bestANN, &currentANN, sizeof(bestANN));
            }
        }
        return best;
    }

    bool findSolution(unsigned char* publicKey, unsigned char* nonce)
    {
        unsigned int totalErrors = computeScore(publicKey, nonce);
        if (totalErrors <= solutionThreshold)
        {
            return true;
        }

        return false;
    }
};

} // namespace score_generic_lut
