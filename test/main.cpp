#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

// Add tests in separate cpp files
int main(int argc, char* argv[])
{
    int result = Catch::Session().run(argc, argv);
    return result;
}