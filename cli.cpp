#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Configuration
#define SOCKET_PATH "/tmp/neighbor_service.sock"
#define MAX_BUFFER_SIZE 4096

int main() {

    // Create a Unix domain socket
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "ERROR: CLI socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }
    
    // Set up the server address
    sockaddr_un server_addr = {};
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);
    server_addr.sun_path[sizeof(server_addr.sun_path) - 1] = '\0';

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "ERROR: Failed to connect to service: " << strerror(errno) << std::endl;
        close(sockfd);
        return 1;
    }

    // Send the command
    const char* command = "GET_NEIGHBORS";
    if (write(sockfd, command, strlen(command)) < 0) {
        std::cerr << "ERROR: Failed to send command: " << strerror(errno) << std::endl;
        close(sockfd);
        return 1;
    }

    // Read the response
    char buffer[MAX_BUFFER_SIZE];
    std::string response;
    ssize_t bytes_read;

    // Read in a loop until connection is closed by server
    while ((bytes_read = read(sockfd, buffer, MAX_BUFFER_SIZE - 1)) > 0) {
        buffer[bytes_read] = '\0';
        response += buffer;
    }

    // Check if there was an error during read
    if (bytes_read < 0) {
        std::cerr << "ERROR: Failed to read response: " << strerror(errno) << std::endl;
        close(sockfd);
        return 1;
    }

    // Display the response
    if (response.empty()) {
        std::cout << "ERROR: No response received from service." << std::endl;
    } else {
        std::cout << response;
    }

    // Clean up
    close(sockfd);
    return 0;
}