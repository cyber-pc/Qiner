#pragma once

#include <cstring>
#include <iostream>
#include <chrono>

#ifdef _MSC_VER
#include <intrin.h>
#include <winsock2.h>
#pragma comment (lib, "ws2_32.lib")

#else
#include <signal.h>
#include <immintrin.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#endif

#include "Constants.h"

class ServerSocket
{
public:
#ifdef _MSC_VER
    ServerSocket()
    {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~ServerSocket()
    {
        WSACleanup();
    }

    void closeConnection()
    {
        closesocket(serverSocket);
    }

    bool establishConnection(char* address, int nodePortCustom)
    {
        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET)
        {
            printf("Fail to create a socket (%d)!\n", WSAGetLastError());
            return false;
        }

        sockaddr_in addr;
        ZeroMemory(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(nodePortCustom);
        sscanf_s(address, "%hhu.%hhu.%hhu.%hhu", &addr.sin_addr.S_un.S_un_b.s_b1, &addr.sin_addr.S_un.S_un_b.s_b2, &addr.sin_addr.S_un.S_un_b.s_b3, &addr.sin_addr.S_un.S_un_b.s_b4);
        if (connect(serverSocket, (const sockaddr*)&addr, sizeof(addr)))
        {
            printf("Fail to connect to %d.%d.%d.%d (%d)!\n", addr.sin_addr.S_un.S_un_b.s_b1, addr.sin_addr.S_un.S_un_b.s_b2, addr.sin_addr.S_un.S_un_b.s_b3, addr.sin_addr.S_un.S_un_b.s_b4, WSAGetLastError());
            closeConnection();
            return false;
        }

        return true;
    }

    SOCKET serverSocket;
#else
    void closeConnection()
    {
        close(serverSocket);
    }
    bool establishConnection(const char* address, int nodePortCustom = -1)
    {
        int port = nodePortCustom > 0 ? nodePortCustom : DEFAULT_PORT;
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1)
        {
            printf("Fail to create a socket (%d)!\n", errno);
            return false;
        }

        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, address, &addr.sin_addr) <= 0)
        {
            printf("Invalid address/ Address not supported (%s)\n", address);
            return false;
        }

        if (connect(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            printf("Fail to connect to %s (%d)\n", address, errno);
            closeConnection();
            return false;
        }

        return true;
    }

    int serverSocket;
#endif

    bool sendData(char* buffer, unsigned int size)
    {
        while (size)
        {
            int numberOfBytes;
            if ((numberOfBytes = send(serverSocket, buffer, size, 0)) <= 0)
            {
                return false;
            }
            buffer += numberOfBytes;
            size -= numberOfBytes;
        }

        return true;
    }
    bool receiveData(char* buffer, unsigned int size)
    {
        const auto beginningTime = std::chrono::steady_clock::now();
        unsigned long long deltaTime = 0;
        while (size && deltaTime <= 2000)
        {
            int numberOfBytes;
            if ((numberOfBytes = recv(serverSocket, buffer, size, 0)) <= 0)
            {
                return false;
            }
            buffer += numberOfBytes;
            size -= numberOfBytes;
            deltaTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - beginningTime).count();
        }

        return true;
    }

    int receive(char* buffer)
    {
        int numberOfBytes = recv(serverSocket, buffer, 1024, 0);
        return numberOfBytes;
    }
};

class ServerSocket2
{
public:
    ServerSocket2(int port, bool nonBlocking = false)
    {
        _nonBlockingMode = nonBlocking;
        _port = port;
        _connectionSts = 0;
        int addrlen = sizeof(_address);

        // Create socket
        if ((_serverFd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            perror("Socket failed");
            _connectionSts = -1;
        }

        int opt = 1;
        setsockopt(_serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        // Bind address
        _address.sin_family = AF_INET;
        _address.sin_addr.s_addr = INADDR_ANY;
        _address.sin_port = htons(_port);
        if (bind(_serverFd, (struct sockaddr *)&_address, sizeof(_address)) < 0)
        {
            perror("Bind failed");
            _connectionSts = -1;
        }
    }

    ~ServerSocket2()
    {
        closeConnection();
    }

    // Listen for connection
    int listenForConnection(int maxConnection = 5)
    {
        if (listen(_serverFd, maxConnection) < 0)
        {
            perror("Listen failed");
            _connectionSts = -1;
            return -1;
        }

        std::cout << "Waiting for a connection ... at port " << _port << std::endl;
        return 0;
    }

    int acceptConnection()
    {
        _serverSocket = accept(_serverFd, (struct sockaddr *)&_address, (socklen_t*)&_address);
        if (_serverSocket < 0)
        {
            perror("Accept failed");
        }

        return _serverSocket;
    }

    int receiveData(char* data, size_t dataSize)
    {
        return recv(_serverSocket, data, dataSize, 0);
    }

    int sendData(char* data, size_t dataSize)
    {
        return send(_serverSocket, data, dataSize, 0);
    }

    void closeSocket()
    {
        if (_serverSocket > 0)
        {
            close(_serverSocket);
        }
    }

    void closeConnection()
    {
        closeSocket();
        if (_serverFd > 0)
        {
            close(_serverFd);
        }
    }

private:
    int _port;
    int _serverFd;
    sockaddr_in _address;
    int _serverSocket;
    int _connectionSts;
    bool _nonBlockingMode;
};