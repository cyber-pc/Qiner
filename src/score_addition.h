#pragma once

#include "score_common.h"
#include "K12AndKeyUtil.h"

#include <cassert>
#include <vector>

namespace score_addition
{

static constexpr unsigned long long NUMBER_OF_INPUT_NEURONS = 2 * 7; // K
static constexpr unsigned long long NUMBER_OF_OUTPUT_NEURONS = 8;    // L
static constexpr unsigned long long NUMBER_OF_TICKS = 120;
static constexpr unsigned long long NUMBER_OF_MUTATIONS = 100;
// Fixed-topology detour: total neuron count is set directly.
static constexpr unsigned long long POPULATION_THRESHOLD = 32;                  // P
// Buffer is sized to N. Effective neighbor count clamps to N-1 (self excluded)
// inside getActualNeighborCount(), keeps maxNumberOfNeighbors even and the existing buffer-center math intact.
static constexpr unsigned long long MAX_NEIGHBOR_NEURONS = POPULATION_THRESHOLD;
static constexpr unsigned int SOLUTION_THRESHOLD = ((1ULL << NUMBER_OF_INPUT_NEURONS) * NUMBER_OF_OUTPUT_NEURONS * 4 / 5);

template <
    unsigned long long numberOfInputNeurons,  // K
    unsigned long long numberOfOutputNeurons, // L
    unsigned long long numberOfTicks,         // N
    unsigned long long maxNumberOfNeighbors,  // 2M
    unsigned long long populationThreshold,   // P
    unsigned long long numberOfMutations,     // S
    unsigned int solutionThreshold>
struct Miner
{
    static constexpr unsigned long long numberOfNeurons =
        numberOfInputNeurons + numberOfOutputNeurons;
    static constexpr unsigned long long maxNumberOfNeurons = populationThreshold;
    static constexpr unsigned long long numberOfEvolutionNeurons =
        populationThreshold - numberOfNeurons;   // P - K - L
    static constexpr unsigned long long maxNumberOfSynapses =
        populationThreshold * maxNumberOfNeighbors;
    static constexpr unsigned long long trainingSetSize = 1ULL << numberOfInputNeurons; // 2^K
    static constexpr unsigned long long paddingNumberOfSynapses =
        (maxNumberOfSynapses + 31 ) / 32 * 32; // padding to multiple of 32
    // Packed 2-bit synapse storage: 4 weights per byte. Encoding:
    //   00 -> 0, 01 -> +1, 10 -> -1, 11 -> 0
    static constexpr unsigned long long packedSynapsesBytes = (maxNumberOfSynapses + 3) / 4;

    static_assert(
        maxNumberOfSynapses <= (0xFFFFFFFFFFFFFFFF << 1ULL),
        "maxNumberOfSynapses must less than or equal MAX_UINT64/2");
    static_assert(maxNumberOfNeighbors % 2 == 0, "maxNumberOfNeighbors must divided by 2");
    static_assert(
        populationThreshold > numberOfNeurons,
        "populationThreshold must be greater than numberOfNeurons");

    // Read-only random2 pool used by initializeANN()/computeScoreFromParent(). Either owned
    // (initialize() generates it) or borrowed (setPool() - lets many engines share one 512MB
    // pool, e.g. one per grinder thread).
    const unsigned char* poolVec = nullptr;
    std::vector<unsigned char> ownedPool;

    void initialize(unsigned char miningSeed[32])
    {
        // Init random2 pool with mining seed
        ownedPool.resize(POOL_VEC_PADDING_SIZE);
        generateRandom2Pool(miningSeed, ownedPool.data());
        poolVec = ownedPool.data();
    }

    void setPool(const unsigned char* pool)
    {
        poolVec = pool;
    }

    // Training set
    struct TraningPair
    {
        char input[numberOfInputNeurons]; // numberOfInputNeurons / 2 bits of A , and B (values: -1 or +1)
        char output[numberOfOutputNeurons];  // numberOfOutputNeurons bits of C (values: -1 or +1)
    } trainingSet[trainingSetSize];       // training set size: 2^K

    struct Synapse
    {
        char weight;
    };

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
        char value;
        bool markForRemoval;
    };

    // Data for roll back
    struct ANN
    {
        Neuron neurons[maxNumberOfNeurons];
        unsigned char synapsesPacked[packedSynapsesBytes];
        unsigned long long population;
    };
    ANN bestANN;
    ANN currentANN;
    // Ant-colony, holds a derived per-identity root, kept distinct from currentANN/bestANN so it can
    // be passed as the parent to computeScoreFromParent() without aliasing currentANN.
    ANN rootScratchANN;

    // Decoded synapse buffer (derived from currentANN.synapsesPacked).
    Synapse synapses[maxNumberOfSynapses];

    struct InitValue
    {
        unsigned long long outputNeuronPositions[numberOfOutputNeurons];
        unsigned long long evolutionNeuronPositions[numberOfEvolutionNeurons];
        unsigned long long synapseWeight[paddingNumberOfSynapses / 32]; // each 64bits elements will
                                                                        // decide value of 32 synapses
        unsigned long long synapseMutation[numberOfMutations];
    } initValue;

    // Get the pointer to all outgoing synapses of a neuron.
    Synapse* getSynapses(unsigned long long neuronIndex)
    {
        return &synapses[neuronIndex * maxNumberOfNeighbors];
    }

    // Refresh the decoded synapses[] buffer from currentANN.synapsesPacked.
    void decodeSynapses()
    {
        // Encoding: 00 -> 0, 01 -> +1, 10 -> -1, 11 -> 0
        static constexpr char weightFromBits[4] = { 0, +1, -1, 0 };
        for (unsigned long long i = 0; i < maxNumberOfSynapses; ++i)
        {
            // Byte location: 4 weights per byte -> currentANN.synapsesPacked[i / 4]
            // Slot location in byte: (i % 4) * 2
            // Keep 2 bits: & 0x3U
            unsigned char ev = (currentANN.synapsesPacked[i / 4] >> ((i % 4) * 2)) & 0x3U;
            synapses[i].weight = weightFromBits[ev];
        }
    }

    unsigned long long neuronIndices[maxNumberOfNeurons];
    char previousNeuronValue[maxNumberOfNeurons];

    unsigned long long outputNeuronIndices[numberOfOutputNeurons];
    char outputNeuronExpectedValue[numberOfOutputNeurons];

    long long neuronValueBuffer[maxNumberOfNeurons];

    unsigned long long getActualNeighborCount() const
    {
        unsigned long long population = currentANN.population;
        unsigned long long maxNeighbors = population - 1;  // Exclude self
        unsigned long long actual = std::min(maxNumberOfNeighbors, maxNeighbors);
        
        return actual;
    }

    unsigned long long getLeftNeighborCount() const
    {
        unsigned long long actual = getActualNeighborCount();
        // For odd number, we add extra for the left
        return (actual + 1) / 2;
    }

    unsigned long long getRightNeighborCount() const
    {
        return getActualNeighborCount() - getLeftNeighborCount();
    }

    // Get the starting index in synapse buffer (left side start)
    unsigned long long getSynapseStartIndex() const
    {
        constexpr unsigned long long synapseBufferCenter = maxNumberOfNeighbors / 2;
        return synapseBufferCenter - getLeftNeighborCount();
    }

    // Get the ending index in synapse buffer (exclusive)
    unsigned long long getSynapseEndIndex() const
    {
        constexpr unsigned long long synapseBufferCenter = maxNumberOfNeighbors / 2;
        return synapseBufferCenter + getRightNeighborCount();
    }

    // Convert buffer index to neighbor offset
    long long bufferIndexToOffset(unsigned long long bufferIdx) const
    {
        constexpr long long synapseBufferCenter = maxNumberOfNeighbors / 2;
        if (bufferIdx < synapseBufferCenter)
        {
            return (long long)bufferIdx - synapseBufferCenter;  // Negative (left)
        }
        else
        {
            return (long long)bufferIdx - synapseBufferCenter + 1;  // Positive (right), skip 0
        }
    }

    // Convert neighbor offset to buffer index
    long long offsetToBufferIndex(long long offset) const
    {
        constexpr long long synapseBufferCenter = maxNumberOfNeighbors / 2;
        if (offset == 0)
        {
            return -1;  // Invalid, exclude self
        }
        else if (offset < 0)
        {
            return synapseBufferCenter + offset;
        }
        else
        {
            return synapseBufferCenter + offset - 1;
        }
    }

    long long getIndexInSynapsesBuffer(long long neighborOffset) const
    {
        long long leftCount = (long long)getLeftNeighborCount();
        long long rightCount = (long long)getRightNeighborCount();
        
        if (neighborOffset == 0 || 
            neighborOffset < -leftCount || 
            neighborOffset > rightCount)
        {
            return -1;
        }

        return offsetToBufferIndex(neighborOffset);
    }



    // Bit-flip mutation on the 2-bit packed weight encoding.
    //   +1 (01) flipped on either bit -> 0 (00 or 11), never -1
    //   -1 (10) flipped on either bit -> 0 (11 or 00), never +1
    //   0  (00) -> +1 or -1 depending on which bit is flipped
    //   0  (11) -> +1 or -1 depending on which bit is flipped (opposite of 00)
    void mutate(unsigned long long synapseMutation)
    {
        // Seed split: bit 0 -> which of the 2 bits to flip; bits 1..63 -> synapse pick
        unsigned long long population = currentANN.population;
        unsigned long long actualNeighbors = getActualNeighborCount();

        unsigned long long totalValidSynapses = population * actualNeighbors;
        unsigned long long flatIdx = (synapseMutation >> 1) % totalValidSynapses;

        unsigned long long neuronIdx = flatIdx / actualNeighbors;
        unsigned long long localSynapseIdx = flatIdx % actualNeighbors;

        unsigned long long synapseIndex = localSynapseIdx + getSynapseStartIndex();
        unsigned long long synapseFullBufferIdx = neuronIdx * maxNumberOfNeighbors + synapseIndex;

        // which of the 2 bits will be flipped
        unsigned long long bitOffset = synapseMutation & 1ULL;
        // byte location: 4 weights per byte
        unsigned long long byteIdx = synapseFullBufferIdx / 4;
        // which 2-bit slot in that byte (0..3)
        unsigned long long nibblePos = synapseFullBufferIdx % 4;
        // get mask to the set bit
        unsigned char mask  = 1u << (nibblePos * 2 + bitOffset);
        // flip the bit, others untouched
        currentANN.synapsesPacked[byteIdx] ^= mask;
    }

    // Calculate the new neuron index that is reached by moving from the given `neuronIdx` `value`
    // neurons to the right or left. Negative `value` moves to the left, positive `value` moves to
    // the right. The return value is clamped in a ring buffer fashion, i.e. moving right of the
    // rightmost neuron continues at the leftmost neuron.
    unsigned long long clampNeuronIndex(long long neuronIdx, long long value)
    {
        unsigned long long population = currentANN.population;
        assert(value > -(long long)population && value < (long long)population 
           && "clampNeuronIndex: |value| must be less than population");

        long long nnIndex = 0;
        // Calculate the neuron index (ring structure)
        if (value >= 0)
        {
            nnIndex = neuronIdx + value;
        }
        else
        {
            nnIndex = neuronIdx + population + value;
        }
        nnIndex = nnIndex % population;
        return (unsigned long long)nnIndex;
    }

    void processTick()
    {
        unsigned long long population = currentANN.population;
        Neuron* neurons = currentANN.neurons;

        // Memset value of current one
        memset(neuronValueBuffer, 0, sizeof(neuronValueBuffer));

        // Loop though all neurons
        unsigned long long startSynapseBufferIdx = getSynapseStartIndex();
        unsigned long long endSynapseBufferIdx = getSynapseEndIndex();

        for (long long n = 0; n < population; ++n)
        {
            const Synapse* kSynapses = getSynapses(n);
            long long neuronValue = neurons[n].value;
            // Scan through all neighbor neurons and sum all connected neurons.
            for (unsigned long long m = startSynapseBufferIdx; m < endSynapseBufferIdx; m++)
            {
                char synapseWeight = kSynapses[m].weight;
                long long offset = bufferIndexToOffset(m);
                unsigned long long nnIndex = clampNeuronIndex(n, offset);

                // Weight-sum
                neuronValueBuffer[nnIndex] += synapseWeight * neuronValue;
            }
        }

        // Clamp the neuron value
        for (long long n = 0; n < population; ++n)
        {
            // Only non input neurons are updated
            if (Neuron::kInput != neurons[n].type)
            {
                long long neuronValue = clampNeuron(neuronValueBuffer[n]);
                neurons[n].value = neuronValue;
            }
        }
    }
    void loadTrainingData(unsigned long long trainingIndex)
    {
        unsigned long long population = currentANN.population;
        Neuron* neurons = currentANN.neurons;

        const auto& data = trainingSet[trainingIndex];
        // Load the input neuron value
        unsigned long long inputIndex = 0;
        for (unsigned long long n = 0; n < population; ++n)
        {
            // Init as zeros
            neurons[n].value = 0;
            if (Neuron::kInput == neurons[n].type)
            {
                neurons[n].value = data.input[inputIndex];
                inputIndex++;
            }
        }

        // Load the expected output value
        memcpy(outputNeuronExpectedValue, data.output, sizeof(outputNeuronExpectedValue[0]) * numberOfOutputNeurons);
    }
    // Tick simulation only runs on one ANN
    void runTickSimulation(unsigned long long trainingIndex)
    {
        unsigned long long population = currentANN.population;
        Neuron* neurons = currentANN.neurons;

        // Load the training set and fill ANN value
        loadTrainingData(trainingIndex);

        // Save the neuron value for comparison
        for (unsigned long long i = 0; i < population; ++i)
        {
            // Backup the neuron value
            previousNeuronValue[i] = neurons[i].value;
        }

        for (unsigned long long tick = 0; tick < numberOfTicks; ++tick)
        {
            processTick();
            // Check exit conditions:
            // - N ticks have passed (already in for loop)
            // - All neuron values are unchanged
            // - All output neurons have non-zero values
            bool allNeuronsUnchanged = true;
            bool allOutputNeuronsIsNonZeros = true;
            for (long long n = 0; n < population; ++n)
            {
                // Neuron unchanged check
                if (previousNeuronValue[n] != neurons[n].value)
                {
                    allNeuronsUnchanged = false;
                }

                // Ouput neuron value check
                if (neurons[n].type == Neuron::kOutput && neurons[n].value == 0)
                {
                    allOutputNeuronsIsNonZeros = false;
                }
            }

            if (allOutputNeuronsIsNonZeros || allNeuronsUnchanged)
            {
                break;
            }

            // Copy the neuron value
            for (long long n = 0; n < population; ++n)
            {
                previousNeuronValue[n] = neurons[n].value;
            }
        }
    }

    unsigned int computeMatchingOutput()
    {
        unsigned long long population = currentANN.population;
        Neuron* neurons = currentANN.neurons;

        // Compute the non-matching value R between output neuron value and initial value
        // Because the output neuron order never changes, the order is preserved
        unsigned int R = 0;
        unsigned long long outputIdx = 0;
        for (unsigned long long i = 0; i < population; i++)
        {
            if (neurons[i].type == Neuron::kOutput)
            {
                if (neurons[i].value == outputNeuronExpectedValue[outputIdx])
                {
                    R++;
                }
                outputIdx++;
            }
        }
        return R;
    }

    // Generate all 2^K possible (A, B, C) pairs
    void generateTrainingSet()
    {
        static constexpr long long boundValue = (1LL << (numberOfInputNeurons / 2)) / 2;
        unsigned long long index = 0;
        for (long long A = -boundValue; A < boundValue; A++)
        {
            for (long long B = -boundValue; B < boundValue; B++)
            {
                long long C = A + B;

                toTenaryBits<numberOfInputNeurons / 2>(A, trainingSet[index].input);
                toTenaryBits<numberOfInputNeurons / 2>(
                    B, trainingSet[index].input + numberOfInputNeurons / 2);
                toTenaryBits<numberOfOutputNeurons>(C, trainingSet[index].output);
                index++;
            }
        }
    }

    unsigned int inferANN()
    {
        // Synapses live as packed 2-bit values in currentANN.synapsesPacked.
        // Decoded char buffer once per inference.
        decodeSynapses();

        unsigned int score = 0;
        for (unsigned long long i = 0; i < trainingSetSize; ++i)
        {
            // Ticks simulation
            runTickSimulation(i);

            // Compute R
            unsigned int R = computeMatchingOutput();
            score += R;
        }
        return score;
    }

    unsigned int initializeANN(unsigned char* publicKey, unsigned char* nonce)
    {
        unsigned char hash[32];
        unsigned char combined[64];
        memcpy(combined, publicKey, 32);
        memcpy(combined + 32, nonce, 32);
        KangarooTwelve(combined, 64, hash, 32);

        unsigned long long& population = currentANN.population;
        Neuron* neurons = currentANN.neurons;

        // Initialization -- fixed-topology: population is N total, set once.
        population = populationThreshold;

        // Generate all 2^K possible (A, B, C) pairs
        generateTrainingSet();

        // Initalize with nonce and public key
        random2(hash, poolVec, (unsigned char*)&initValue, sizeof(InitValue));

        // Randomly choose the positions of neurons types.
        // Default = Input.
        for (unsigned long long i = 0; i < population; ++i)
        {
            neuronIndices[i] = i;
            neurons[i].type = Neuron::kInput;
        }
        unsigned long long neuronCount = population;
        // Output positions from the remaining pool
        for (unsigned long long i = 0; i < numberOfOutputNeurons; ++i)
        {
            unsigned long long outputNeuronIdx = initValue.outputNeuronPositions[i] % neuronCount;

            // Fill the neuron type
            neurons[neuronIndices[outputNeuronIdx]].type = Neuron::kOutput;
            outputNeuronIndices[i] = neuronIndices[outputNeuronIdx];

            // This index is used, copy the end of indices array to current position and decrease
            // the number of picking neurons
            neuronCount = neuronCount - 1;
            neuronIndices[outputNeuronIdx] = neuronIndices[neuronCount];
        }

        // Evolution positions from the remaining pool
        for (unsigned long long i = 0; i < numberOfEvolutionNeurons; ++i)
        {
            unsigned long long evolutionNeuronIdx = initValue.evolutionNeuronPositions[i] % neuronCount;

            neurons[neuronIndices[evolutionNeuronIdx]].type = Neuron::kEvolution;

            neuronCount = neuronCount - 1;
            neuronIndices[evolutionNeuronIdx] = neuronIndices[neuronCount];
        }

        // Synapse weight initialization, already in the 2-bit packed, just copy them
        memcpy(currentANN.synapsesPacked,
               initValue.synapseWeight,
               sizeof(currentANN.synapsesPacked));

        // Run the first inference to get starting point before mutation
        unsigned int score = inferANN();

        return score;
    }

    // Main function for mining
    unsigned int computeScore(unsigned char* publicKey, unsigned char* nonce)
    {
        // Initialize
        unsigned int bestR = initializeANN(publicKey, nonce);
        memcpy(&bestANN, &currentANN, sizeof(bestANN));

        for (unsigned long long s = 0; s < numberOfMutations; ++s)
        {
            mutate(initValue.synapseMutation[s]);

            // Ticks simulation
            unsigned int R = inferANN();

            // Roll back if neccessary
            if (R >= bestR)
            {
                bestR = R;
                // Better R. Save the state
                memcpy(&bestANN, &currentANN, sizeof(bestANN));
            }
            else
            {
                // Roll back
                memcpy(&currentANN, &bestANN, sizeof(bestANN));
            }
        }
        return bestR;
    }

    bool findSolution(unsigned char* publicKey, unsigned char* nonce)
    {
        unsigned int score = computeScore(publicKey, nonce);
        if (score >= solutionThreshold)
        {
            return true;
        }

        return false;
    }

    // Ant-colony: derive this identity's per-epoch root ANN = initializeANN(K12(identityPublicKey || spectrum digest)),
    // Freshly initialize currentANN into rootScratchANN and returns it, so it can be passed as the parent to computeScoreFromParent()
    // without aliasing currentANN. initializeANN() also generates the seed-independent training set
    const ANN& deriveRootANN(unsigned char* identityPublicKey, unsigned char* seed)
    {
        initializeANN(identityPublicKey, seed);
        memcpy(&rootScratchANN, &currentANN, sizeof(ANN));
        return rootScratchANN;
    }

    // Ant-colony: score a child by evolving from a parent's ANN state instead of a freshly generated
    // topology. Semantically identical to computeScore() except the topology + packed synapses come from
    // the parent (loaded into currentANN), the child's mutation walk seeds from
    // K12(publicKey || nonce || anchorTickDigest). Binding the anchor tick's digest means the walk
    // cannot be computed before the anchor tick exists; freshness caps publication at N ticks after it.
    // Precondition: the training set is already generated (call deriveRootANN()/initializeANN() once first),
    // this method does not regenerate it.
    unsigned int computeScoreFromParent(const ANN& parentANN, unsigned char* publicKey, unsigned char* nonce,
                                        const unsigned char* anchorTickDigest)
    {
        // Load parent topology + packed synapses into currentANN.
        memcpy(currentANN.neurons, parentANN.neurons, sizeof(parentANN.neurons));
        memcpy(currentANN.synapsesPacked, parentANN.synapsesPacked, sizeof(parentANN.synapsesPacked));
        currentANN.population = parentANN.population;

        // Child mutation seeds from K12(publicKey || nonce || anchorTickDigest).
        unsigned char hash[32];
        unsigned char combined[96];
        memcpy(combined, publicKey, 32);
        memcpy(combined + 32, nonce, 32);
        memcpy(combined + 64, anchorTickDigest, 32);
        KangarooTwelve(combined, 96, hash, 32);
        random2(hash, poolVec, (unsigned char*)&initValue, sizeof(InitValue));

        // Baseline: re-derive the parent's score from the staged state.
        unsigned int bestR = inferANN();
        memcpy(&bestANN, &currentANN, sizeof(bestANN));

        // Evolve (identical loop to computeScore()).
        for (unsigned long long s = 0; s < numberOfMutations; ++s)
        {
            mutate(initValue.synapseMutation[s]);
            unsigned int R = inferANN();
            if (R >= bestR)
            {
                bestR = R;
                memcpy(&bestANN, &currentANN, sizeof(bestANN));
            }
            else
            {
                memcpy(&currentANN, &bestANN, sizeof(bestANN));
            }
        }
        return bestR;
    }
};

} // namespace score_addition
