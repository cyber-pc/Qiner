#include "score_addition.h"

#include <catch2/catch.hpp>
#include <memory>
#include <set>

using namespace score_addition;

static constexpr long long TEST_NUMBER_OF_INPUT_NEURONS = 14;
static constexpr long long TEST_NUMBER_OF_OUTPUT_NEURONS = 8;
static constexpr long long TEST_NUMBER_OF_TICKS = 1000;
static constexpr long long TEST_MAX_NUMBER_OF_NEIGHBORS = 728;
static constexpr long long TEST_NUMBER_OF_MUTATIONS = 100;
static constexpr long long TEST_POPULATION_THRESHOLD =
    TEST_NUMBER_OF_INPUT_NEURONS + TEST_NUMBER_OF_OUTPUT_NEURONS + TEST_NUMBER_OF_MUTATIONS;
static constexpr int TEST_SOLUTION_THRESHOLD = 60000;

using TestMiner = Miner<
    TEST_NUMBER_OF_INPUT_NEURONS,
    TEST_NUMBER_OF_OUTPUT_NEURONS,
    TEST_NUMBER_OF_TICKS,
    TEST_MAX_NUMBER_OF_NEIGHBORS,
    TEST_POPULATION_THRESHOLD,
    TEST_NUMBER_OF_MUTATIONS,
    TEST_SOLUTION_THRESHOLD>;

class TestFixture
{
public:
    std::unique_ptr<TestMiner> miner;
    unsigned char miningSeed[32] = {0};
    unsigned char publicKey[32] = {0};
    unsigned char nonce[32] = {0};

    TestFixture()
    {
        // Deterministic seed
        for (int i = 0; i < 32; i++)
        {
            miningSeed[i] = i;
            publicKey[i] = i + 32;
            nonce[i] = i + 64;
        }

        miner = std::make_unique<TestMiner>();
        miner->initialize(miningSeed);
    }

    void initializeANN() { miner->initializeANN(publicKey, nonce); }

    void setPopulation(unsigned long long pop) { miner->currentANN.population = pop; }
};

// Helper functions
TEST_CASE("clampNeuron", "[helpers]")
{
    SECTION("Value within range unchanged")
    {
        REQUIRE(clampNeuron(0) == 0);
        REQUIRE(clampNeuron(1) == 1);
        REQUIRE(clampNeuron(-1) == -1);
    }

    SECTION("Value above 1 clamped to 1")
    {
        REQUIRE(clampNeuron(2) == 1);
        REQUIRE(clampNeuron(100) == 1);
        REQUIRE(clampNeuron(1000000LL) == 1);
    }

    SECTION("Value below -1 clamped to -1")
    {
        REQUIRE(clampNeuron(-2) == -1);
        REQUIRE(clampNeuron(-100) == -1);
        REQUIRE(clampNeuron(-1000000LL) == -1);
    }
}

TEST_CASE("toTenaryBits", "[helpers]")
{
    SECTION("Convert 0 to ternary bits")
    {
        char bits[7];
        toTenaryBits<7>(0, bits);
        // 0 in binary: all bits are 0, so all outputs are -1
        for (int i = 0; i < 7; i++)
        {
            REQUIRE(bits[i] == -1);
        }
    }

    SECTION("Convert positive number")
    {
        char bits[7];
        toTenaryBits<7>(5, bits); // 5 = 101 in binary
        REQUIRE(bits[0] == 1);    // LSB = 1
        REQUIRE(bits[1] == -1);   // bit 1 = 0 -> -1
        REQUIRE(bits[2] == 1);    // bit 2 = 1
        for (int i = 3; i < 7; i++)
        {
            REQUIRE(bits[i] == -1);
        }
    }

    SECTION("Convert -1 (all 1s in two's complement)")
    {
        char bits[7];
        toTenaryBits<7>(-1, bits);
        // -1 has all bits set to 1
        for (int i = 0; i < 7; i++)
        {
            REQUIRE(bits[i] == 1);
        }
    }
}

// Miner functions
TEST_CASE("counting", "[neighbor]")
{
    TestFixture fixture;
    SECTION("Population")
    {
        // Full connected when population smaller than number of neighbor
        fixture.setPopulation(TEST_MAX_NUMBER_OF_NEIGHBORS / 2);
        REQUIRE(fixture.miner->getActualNeighborCount() == (TEST_MAX_NUMBER_OF_NEIGHBORS / 2 - 1));

        // Population > neighbors
        fixture.setPopulation(TEST_MAX_NUMBER_OF_NEIGHBORS * 2);
        REQUIRE(fixture.miner->getActualNeighborCount() == TEST_MAX_NUMBER_OF_NEIGHBORS);
    }

    SECTION("Left right")
    {
        // Even neighbor count, symetric split
        fixture.setPopulation(23); // 22 neighbors
        REQUIRE(fixture.miner->getActualNeighborCount() == 22);
        REQUIRE(fixture.miner->getLeftNeighborCount() == 11);
        REQUIRE(fixture.miner->getRightNeighborCount() == 11);

        // Odd neighbor count, left gets extra
        fixture.setPopulation(22); // 21 neighbors
        REQUIRE(fixture.miner->getActualNeighborCount() == 21);
        REQUIRE(fixture.miner->getLeftNeighborCount() == 11);
        REQUIRE(fixture.miner->getRightNeighborCount() == 10);

        // Population > neighbors and even number of neigbor
        fixture.setPopulation(TEST_MAX_NUMBER_OF_NEIGHBORS * 2);
        REQUIRE(TEST_MAX_NUMBER_OF_NEIGHBORS % 2 == 0);
        REQUIRE(fixture.miner->getActualNeighborCount() == TEST_MAX_NUMBER_OF_NEIGHBORS);
        REQUIRE(fixture.miner->getLeftNeighborCount() == TEST_MAX_NUMBER_OF_NEIGHBORS / 2);
        REQUIRE(fixture.miner->getRightNeighborCount() == TEST_MAX_NUMBER_OF_NEIGHBORS / 2);

        // Make sure sum of left and right always equal total of neighbor count
        for (unsigned long long pop = 22; pop <= 500; pop++)
        {
            fixture.setPopulation(pop);
            unsigned long long actual = fixture.miner->getActualNeighborCount();
            unsigned long long left = fixture.miner->getLeftNeighborCount();
            unsigned long long right = fixture.miner->getRightNeighborCount();
            REQUIRE(left + right == actual);
        }
    }
}

TEST_CASE("index", "[neighbor]")
{
    TestFixture fixture;
    constexpr unsigned long long halfMax = TEST_MAX_NUMBER_OF_NEIGHBORS / 2;

    // Test assume non-optimized version that allocate a big buffer of synapses
    SECTION("Population < TEST_MAX_NUMBER_OF_NEIGHBORS")
    {
        // Row of synapse buffer [0..353..364..374 ..727], only use [353 .. 374) range of row
        // synapse buffer
        fixture.setPopulation(22); // 21 neighbors -> left=11, right=10
        unsigned long long start = fixture.miner->getSynapseStartIndex();
        unsigned long long end = fixture.miner->getSynapseEndIndex();

        REQUIRE(start == halfMax - 11); // 364 - 11 = 353
        REQUIRE(end == halfMax + 10);   // 364 + 10 = 374
        REQUIRE(end - start == 21);
    }

    SECTION("Population > TEST_MAX_NUMBER_OF_NEIGHBORS - full range")
    {
        fixture.setPopulation(TEST_MAX_NUMBER_OF_NEIGHBORS * 2);
        unsigned long long start = fixture.miner->getSynapseStartIndex();
        unsigned long long end = fixture.miner->getSynapseEndIndex();

        REQUIRE(start == 0);
        REQUIRE(end == TEST_MAX_NUMBER_OF_NEIGHBORS);
    }

    SECTION("Range is contiguous and correct size")
    {
        for (unsigned long long pop = 22; pop <= 500; pop++)
        {
            fixture.setPopulation(pop);
            unsigned long long start = fixture.miner->getSynapseStartIndex();
            unsigned long long end = fixture.miner->getSynapseEndIndex();
            unsigned long long actual = fixture.miner->getActualNeighborCount();

            REQUIRE(end > start);
            REQUIRE(end - start == actual);
            REQUIRE(start >= 0);
            REQUIRE(end <= TEST_MAX_NUMBER_OF_NEIGHBORS);
        }
    }
}

TEST_CASE("bufferIndexAndOffset", "[conversion]")
{
    TestFixture fixture;
    fixture.setPopulation(22);
    constexpr long long halfMax = TEST_MAX_NUMBER_OF_NEIGHBORS / 2; // 364

    // Synapse row buffer [0..364..727]
    SECTION("Left side indices")
    {
        // Buffer index to neighbor offset
        REQUIRE(fixture.miner->bufferIndexToOffset(363) == -1);  // Closest left
        REQUIRE(fixture.miner->bufferIndexToOffset(354) == -10); // 10th left
        REQUIRE(fixture.miner->bufferIndexToOffset(0) == -364);  // Furthest left

        // Neighbor offset to biffer index
        REQUIRE(fixture.miner->offsetToBufferIndex(-1) == 363);
        REQUIRE(fixture.miner->offsetToBufferIndex(-10) == 354);
        REQUIRE(fixture.miner->offsetToBufferIndex(-364) == 0);

        // Valid left offsets
        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(-1) >= 0);
        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(-11) >= 0);
    }

    SECTION("Right side indices")
    {
        // Buffer index to neighbor offset
        REQUIRE(fixture.miner->bufferIndexToOffset(364) == 1);   // Closest right
        REQUIRE(fixture.miner->bufferIndexToOffset(373) == 10);  // 10th right
        REQUIRE(fixture.miner->bufferIndexToOffset(727) == 364); // Furthest right

        REQUIRE(fixture.miner->offsetToBufferIndex(1) == 364);
        REQUIRE(fixture.miner->offsetToBufferIndex(10) == 373);
        REQUIRE(fixture.miner->offsetToBufferIndex(364) == 727);

        // Valid right offsets
        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(1) >= 0);
        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(10) >= 0);
    }

    SECTION("Center point (halfMax) maps to +1 because the layout of synapse buffer ignore self")
    {
        REQUIRE(fixture.miner->bufferIndexToOffset(halfMax) == 1);
        REQUIRE(fixture.miner->bufferIndexToOffset(halfMax - 1) == -1);
        REQUIRE(fixture.miner->offsetToBufferIndex(0) == -1);

        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(0) == -1);

        // Out of range left
        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(-12) == -1);
        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(-100) == -1);

        // Out of range right
        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(11) == -1);
        REQUIRE(fixture.miner->getIndexInSynapsesBuffer(100) == -1);
    }

    SECTION("Repeat: bufferIndex -> offset -> bufferIndex")
    {
        for (long long idx = 0; idx < MAX_NEIGHBOR_NEURONS; idx++)
        {
            long long offset = fixture.miner->bufferIndexToOffset(idx);
            REQUIRE(offset != 0); // Never returns 0 because we exclude self neuron
            long long bufferIndex = fixture.miner->offsetToBufferIndex(offset);
            REQUIRE(bufferIndex == idx);
        }
    }
}

TEST_CASE("clampNeuronIndex", "[neuron]")
{
    TestFixture fixture;
    fixture.setPopulation(22);

    // Normal range
    REQUIRE(fixture.miner->clampNeuronIndex(0, 5) == 5);
    REQUIRE(fixture.miner->clampNeuronIndex(10, 5) == 15);
    REQUIRE(fixture.miner->clampNeuronIndex(10, -5) == 5);
    REQUIRE(fixture.miner->clampNeuronIndex(5, -3) == 2);

    // At boundaries
    REQUIRE(fixture.miner->clampNeuronIndex(20, 5) == 3);  // neuron 20: 21 0 1 2 3
    REQUIRE(fixture.miner->clampNeuronIndex(21, 1) == 0);  // neuron 21: 0
    REQUIRE(fixture.miner->clampNeuronIndex(0, -1) == 21); // neuron 0: 21
    REQUIRE(fixture.miner->clampNeuronIndex(2, -5) == 19); // neuron 2: 1 0 21 20 19

    // Zero offset.
    REQUIRE(fixture.miner->clampNeuronIndex(0, 0) == 0);
    REQUIRE(fixture.miner->clampNeuronIndex(10, 0) == 10);
    REQUIRE(fixture.miner->clampNeuronIndex(21, 0) == 21);
}

TEST_CASE("getNeighborNeuronIndex", "[neuron]")
{
    TestFixture fixture;

    SECTION("Maps local index to correct neuron")
    {
        fixture.setPopulation(23);      // 22 neighbors, left=11, right=11
        unsigned long long center = 11; // Test from neuron 11

        // First 11 indices [0-10] are left neighbors [0 10]
        // k=0 -> center -11 : most left
        // k=10 -> center -1
        REQUIRE(fixture.miner->getNeighborNeuronIndex(center, 0) == 0);   // 0 -> 0
        REQUIRE(fixture.miner->getNeighborNeuronIndex(center, 10) == 10); // 10 -> 10

        // Next 11 indices (11-21) are right neighbors [12 - 22]
        // k=11 -> center +1
        // k=21 -> center +11 : most right
        REQUIRE(fixture.miner->getNeighborNeuronIndex(center, 11) == 12); // 11 -> 12
        REQUIRE(fixture.miner->getNeighborNeuronIndex(center, 21) == 22); // 21 -> 22

        fixture.setPopulation(22); // 21 neighbors, left=11, right=10

        // First 11 indices (0-10) are left neighbors [0 10]
        REQUIRE(fixture.miner->getNeighborNeuronIndex(center, 0) == 0);   // 0 -> 0
        REQUIRE(fixture.miner->getNeighborNeuronIndex(center, 10) == 10); // 10 -> 10

        // Next 10 indices (11-20) are right neighbors [11 - 21]
        REQUIRE(fixture.miner->getNeighborNeuronIndex(center, 11) == 12); // 11 -> 12
        REQUIRE(fixture.miner->getNeighborNeuronIndex(center, 20) == 21); // 20 -11 -> 21

        // Never return its own neuron index, and neiborh index are unique
        fixture.setPopulation(22);
        unsigned long long actualNeighbors = fixture.miner->getActualNeighborCount();
        for (unsigned long long center = 0; center < 22; center++)
        {
            std::set<unsigned long long> neighbors;
            for (unsigned long long k = 0; k < actualNeighbors; k++)
            {
                unsigned long long neighbor = fixture.miner->getNeighborNeuronIndex(center, k);
                REQUIRE(neighbor != center);

                REQUIRE(neighbors.find(neighbor) == neighbors.end());
                neighbors.insert(neighbor);
            }
        }
    }

    SECTION("Maps local index wrap-around")
    {
        fixture.setPopulation(22); // 21 neighbors, left=11, right=10
        // From neuron 0, left neighbors wrap to high indices, ring: .. 10 11 12 13 14 15 16 17 18
        // 19 20 21 0 1 2 3 4 5 6 7 8 9 10 ..
        REQUIRE(fixture.miner->getNeighborNeuronIndex(0, 0) == 11); // 0 -> left 11 -> 11
        // From neuron 21, right neighbors wrap to low indices
        REQUIRE(fixture.miner->getNeighborNeuronIndex(21, 20) == 9); // 20 -> right 10 -> 9
    }
}

TEST_CASE("processTick", "[tick]")
{
    TestFixture fixture;
    fixture.initializeANN();

    // Input neurons unchanged after tick"
    // Set specific input values
    for (unsigned long long i = 0; i < fixture.miner->currentANN.population; i++)
    {
        if (fixture.miner->currentANN.neurons[i].type == TestMiner::Neuron::kInput)
        {
            fixture.miner->currentANN.neurons[i].value = 1;
        }
    }

    fixture.miner->processTick();

    for (unsigned long long i = 0; i < fixture.miner->currentANN.population; i++)
    {
        if (fixture.miner->currentANN.neurons[i].type == TestMiner::Neuron::kInput)
        {
            REQUIRE(fixture.miner->currentANN.neurons[i].value == 1);
        }
    }
}

TEST_CASE("insertNeuron", "[insert]")
{
    TestFixture fixture;
    fixture.initializeANN();

    // Count types before
    unsigned long long inputsBefore = 0, outputsBefore = 0;
    for (unsigned long long i = 0; i < fixture.miner->currentANN.population; i++)
    {
        if (fixture.miner->currentANN.neurons[i].type == TestMiner::Neuron::kInput)
            inputsBefore++;
        if (fixture.miner->currentANN.neurons[i].type == TestMiner::Neuron::kOutput)
            outputsBefore++;
    }

    unsigned long long oldPop = fixture.miner->currentANN.population;
    unsigned long long startIdx = fixture.miner->getSynapseStartIndex();

    fixture.miner->insertNeuron(0, startIdx);

    REQUIRE(fixture.miner->currentANN.population == oldPop + 1);
    // Inserted at index 1 (after neuron 0)
    REQUIRE(fixture.miner->currentANN.neurons[1].type == TestMiner::Neuron::kEvolution);

    // Add more neuron
    fixture.miner->insertNeuron(5, startIdx);

    // Count types after
    unsigned long long inputsAfter = 0, outputsAfter = 0;
    for (unsigned long long i = 0; i < fixture.miner->currentANN.population; i++)
    {
        if (fixture.miner->currentANN.neurons[i].type == TestMiner::Neuron::kInput)
            inputsAfter++;
        if (fixture.miner->currentANN.neurons[i].type == TestMiner::Neuron::kOutput)
            outputsAfter++;
    }

    REQUIRE(inputsAfter == inputsBefore);
    REQUIRE(outputsAfter == outputsBefore);
}

TEST_CASE("smallset", "[pipeline]")
{
    TestMiner miner;
    unsigned char miningSeed[32] = {0};
    miner.initialize(miningSeed);

    auto& ann = miner.currentANN;
    ann.population = 22;

    // Initialize neurons: 14 input + 8 output
    for (unsigned long long i = 0; i < 22; i++)
    {
        ann.neurons[i].value = 0;
        ann.neurons[i].markForRemoval = false;
        ann.neurons[i].type = (i < 14) ? TestMiner::Neuron::kInput : TestMiner::Neuron::kOutput;
    }

    // Initialize all synapses to zero
    memset(ann.synapses, 0, sizeof(ann.synapses));

    // Set all 14 input neurons to value = 1
    for (int i = 0; i < 14; i++)
    {
        ann.neurons[i].value = 1;
    }

    // Case1: no insertion
    // ...13 [14] 15 16 17 18 19 20 21 [0] 1 2 ...
    // Select synapse: neuron 0 -> neuron 14 to mutate
    // offset: -8
    // offsetToBufferIndex(-8) = 728 / 2 + (-8) = 356
    // localSynapseIdx = 356 - getSynapseStartIndex() = 356 - 353 = 3
    // flatIdx = neuronIdx * actualNeighbors + localSynapseIdx = 0 * actualNeighbors + 3 = 3
    // Trace back with increasing weight 1 : mutationValue = (flatIdx << 1) | 1 = (3 << 1) | 1 = 7
    miner.initValue.synpaseMutation[0] = 7;

    REQUIRE(miner.getSynapses(0)[miner.offsetToBufferIndex(-8)].weight == 0);

    miner.mutate(0);

    REQUIRE(miner.getSynapses(0)[miner.offsetToBufferIndex(-8)].weight == 1);
    REQUIRE(ann.population == 22);

    // Synapse: neuron 0 -> neuron 14, weight = 1
    // Input: neuron 0 value = 1
    // Expected after tick:
    //   - Input neurons [0-13]: unchanged = 1
    //   - Output neuron [14]: receives 1 * 1 = 1
    //   - Output neurons [15-21]: no input = 0
    miner.processTick();

    REQUIRE(ann.neurons[14].value == 1);
    // input neurons unchanged
    for (int i = 0; i < 14; i++)
    {
        REQUIRE(ann.neurons[i].value == 1);
    }

    // Case2: insertion 1 neuron but remove
    // ... 20 21 0 1 2 3 4 5 6 7 8...
    // Select synapse: neuron 4 -> neuron 8 to mutate
    // offset: 4
    // offsetToBufferIndex(4) = 728 / 2 + (4) - 1 = 367  (subtract 1 for positive offsets!)
    // localSynapseIdx = 367 - getSynapseStartIndex() = 367 - 353 = 14
    // flatIdx = neuronIdx * actualNeighbors + localSynapseIdx = 4 * actualNeighbors + 14 = 4 * 21 + 14 = 98
    // Trace back with increasing weight 1: mutationValue = (flatIdx << 1) | 1 = (98 << 1) | 1 = 197
    miner.initValue.synpaseMutation[1] = 197;
    // set 1 to force inserting synapse then this evo neuron will be remove due to zero conmecyon
    miner.getSynapses(4)[miner.offsetToBufferIndex(4)].weight = 1; 

    miner.mutate(1);
    REQUIRE(miner.getSynapses(4)[miner.offsetToBufferIndex(4)].weight == 1);
    REQUIRE(ann.population == 22);

    // Case3: insertion 1 neuron without removing
    // ... 20 21 0 1 2 3 4 5 6 7 8...
    // Set synapse to avoid removal: neuron 4 -> neuron 6, neuron 5 -> neuron 6, neuron 5 -> neuron 7; 
    // Select synapse: neuron 5 -> neuron 6 to mutate
    // offsetToBufferIndex(6 - 5) = 728 / 2 + (1) - 1 = 364  (subtract 1 for positive offsets!)
    // localSynapseIdx = 367 - getSynapseStartIndex() = 364 - 353 = 11
    // flatIdx = neuronIdx * actualNeighbors + localSynapseIdx = 5 * actualNeighbors + 11 = 5 * 21 + 11 = 116
    // Trace back with increasing weight 1: mutationValue = (flatIdx << 1) | 1 = (116 << 1) | 1 = 233
    miner.initValue.synpaseMutation[2] = 233;
    
    // 5->6
    miner.getSynapses(5)[miner.offsetToBufferIndex(6 - 5)].weight = 1; 
    // 5->7
    miner.getSynapses(5)[miner.offsetToBufferIndex(7 - 5)].weight = 1; 
    // 4->6
    miner.getSynapses(4)[miner.offsetToBufferIndex(6 - 4)].weight = 1; 

    miner.mutate(2);

    // Neuron 6 is the new one
    REQUIRE(ann.neurons[6].type == TestMiner::Neuron::kEvolution);
    REQUIRE(miner.getSynapses(5)[miner.offsetToBufferIndex(6 - 5)].weight == 0);

    // Synapse from 5: old 6 become 7, old 7 become 8
    REQUIRE(miner.getSynapses(5)[miner.offsetToBufferIndex(7 - 5)].weight == 1);
    REQUIRE(miner.getSynapses(5)[miner.offsetToBufferIndex(8 - 5)].weight == 1); 

    // Synapse from 4: old 6 become 7
    REQUIRE(miner.getSynapses(4)[miner.offsetToBufferIndex(7 - 4)].weight == 1); 

    // Neuron population is increased
    REQUIRE(ann.population == 23);
}
