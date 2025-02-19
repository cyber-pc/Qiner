#pragma once
#include <vector>
#include "RequestResponseHeader.h"

class RelayMessage
{
public:
    RelayMessage() = default;

    // TODO: change size to full size of the packet. Not just size of the payload
    int serialize(char* buffer, size_t size) const
    {
        if (size < sizeof(RequestResponseHeader) + payload.size())
        {
            return -1;
        }
        memcpy(buffer, &header, sizeof(RequestResponseHeader));
        memcpy(buffer + sizeof(RequestResponseHeader), payload.data(), payload.size());
        return sizeof(RequestResponseHeader) + payload.size();
    }

    size_t getTotalSizeInBytes() const
    {
        return sizeof(RequestResponseHeader) + payload.size();
    }

    RequestResponseHeader header;
    std::vector<char> payload;
};
