#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <fcntl.h>
#include <ctime>

// Configuration settings
#define BROADCAST_PORT 60000  // Port used for service discovery
#define ANNOUNCE_INTERVAL 10  // Time between broadcasts (seconds)
#define MAX_BUFFER_SIZE 1024  // Maximum size of the receive buffer

/**
 * Sets up a UDP socket to listen for incoming broadcasts on the specified port.
 * The socket is configured to be non-blocking.
 */
int setup_receiver_socket() {
    // Create a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Receiver socket creation failed: " << strerror(errno) << "\n";
        return -1;
    }

    // Set the socket to non-blocking mode
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        std::cerr << "Failed to get socket flags: " << strerror(errno) << "\n";
        close(sockfd);
        return -1;
    }
    
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "Failed to set socket non-blocking: " << strerror(errno) << "\n";
        close(sockfd);
        return -1;
    }

    // Allow multiple sockets to use the same port
    int reuseAddr = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr)) < 0) {
        std::cerr << "Failed to set SO_REUSEADDR: " << strerror(errno) << "\n";
        close(sockfd);
        return -1;
    }

    // Bind to the broadcast port on INADDR_ANY (listen on all interfaces)
    sockaddr_in receiverAddr = {};
    receiverAddr.sin_family = AF_INET;
    receiverAddr.sin_port = htons(BROADCAST_PORT);
    receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (sockaddr*)&receiverAddr, sizeof(receiverAddr)) < 0) {
        std::cerr << "Bind to broadcast port failed: " << strerror(errno) << "\n";
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * Sets up a UDP socket for sending broadcast messages.
 * The socket is configured with the broadcast option enabled.
 */
int setup_broadcast_socket() {
    // Create a UDP socket for broadcasting
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Broadcast socket creation failed: " << strerror(errno) << "\n";
        return -1;
    }

    // Enable broadcasting on this socket
    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0) {
        std::cerr << "Setting broadcast option failed: " << strerror(errno) << "\n";
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * Determines if a network interface can be used for broadcasting.
 * Checks for necessary properties like broadcast capability and non-loopback.
 */
bool is_valid_interface(ifaddrs* ifa) {
    return (ifa->ifa_addr != nullptr && 
            ifa->ifa_flags & IFF_UP && 
            ifa->ifa_addr->sa_family == AF_INET &&
            ifa->ifa_broadaddr != nullptr && 
            !(ifa->ifa_flags & IFF_LOOPBACK) && 
            ifa->ifa_flags & IFF_BROADCAST);
}

/**
 * Gets the IP addresses associated with a network interface.
 * Converts the binary address formats to human-readable strings.
 */
bool extract_ip_addresses(const ifaddrs* ifa, std::string& local_ip, std::string& broadcast_ip) {
    // Convert to IPv4 address format
    const auto* addr = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
    const auto* broadcast = reinterpret_cast<const sockaddr_in*>(ifa->ifa_broadaddr);
    
    // Prepare buffers for the string versions of the addresses
    char local_ip_buf[INET_ADDRSTRLEN] = {};
    char broadcast_ip_buf[INET_ADDRSTRLEN] = {};
    
    // Convert the addresses and check for errors
    if (!inet_ntop(AF_INET, &addr->sin_addr, local_ip_buf, INET_ADDRSTRLEN) ||
        !inet_ntop(AF_INET, &broadcast->sin_addr, broadcast_ip_buf, INET_ADDRSTRLEN)) {
        return false;
    }
    
    // Store results in the provided string references
    local_ip = local_ip_buf;
    broadcast_ip = broadcast_ip_buf;
    return true;
}

/**
 * Retrieves the MAC address for a given network interface.
 * Uses the Linux sysfs filesystem to get hardware address.
 */
bool get_mac_address(const std::string& interface, std::string& mac_address) {
    // MAC addresses in Linux are accessible through the sysfs filesystem
    std::string path = "/sys/class/net/" + interface + "/address";
    
    std::ifstream mac_file(path);
    if (!mac_file.is_open()) {
        return false;
    }
    
    std::getline(mac_file, mac_address);
    return !mac_address.empty();
}

/**
 * Sends a UDP broadcast message to announce this service on the network.
 * The message includes the local IP and MAC address for identification.
 */
bool send_broadcast(int sockfd, const std::string& broadcast_ip, const std::string& local_ip, const std::string& mac_address) {
    // Set up the broadcast address structure
    sockaddr_in broadcastAddr = {};
    broadcastAddr.sin_family = AF_INET;
    broadcastAddr.sin_port = htons(BROADCAST_PORT);
    if (inet_pton(AF_INET, broadcast_ip.c_str(), &broadcastAddr.sin_addr) <= 0) {
        std::cerr << "Invalid broadcast address: " << broadcast_ip << "\n";
        return false;
    }

    // Format the message with identifying information
    // The receiving function will add a timestamp when received
    std::string message = "NEIGHBOR " + local_ip + " " + mac_address;

    // Send the broadcast packet
    if (sendto(sockfd, message.c_str(), message.size(), 0, 
              (sockaddr*)&broadcastAddr, sizeof(broadcastAddr)) < 0) {
        std::cerr << "Broadcast send failed: " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

/**
 * Main discovery function that announces our service on all network interfaces.
 * Iterates through network interfaces and broadcasts on each valid one.
 */
void broadcast_service_presence(int broadcast_sockfd) {
    // Get a list of all network interfaces on this device
    ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get network interfaces: " << strerror(errno) << "\n";
        return;
    }
    
    // Check each interface
    for (ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        // Skip interfaces that aren't suitable for broadcasting
        if (!is_valid_interface(ifa)) {                                                     // TODO: Filter out used subnets
            continue;
        }

        // Get the IP addresses for this interface
        std::string local_ip, broadcast_ip;
        if (!extract_ip_addresses(ifa, local_ip, broadcast_ip)) {
            std::cerr << "Failed to extract IP addresses for interface " << ifa->ifa_name << "\n";
            continue;
        }
            
        // Get the MAC address for identification
        std::string mac_address;
        if (!get_mac_address(ifa->ifa_name, mac_address)) {
            std::cerr << "Failed to get MAC address for interface " << ifa->ifa_name << "\n";
            continue;
        }
            
        // Announce our presence on this interface
        if (!send_broadcast(broadcast_sockfd,broadcast_ip, local_ip, mac_address)) {
            std::cerr << "Failed to send broadcast on interface " << ifa->ifa_name << "\n";
        } else {
            // Log successful broadcast
            std::time_t now = std::time(nullptr);
            char time_str[9];
            std::strftime(time_str, sizeof(time_str), "%H:%M:%S", std::localtime(&now));
            std::cout << time_str << ": Broadcast sent from " << ifa->ifa_name << " (" << local_ip 
                      << ") to " << broadcast_ip << " (MAC: " << mac_address << ")\n";
        }
    }
    
    // Free the memory allocated by getifaddrs
    freeifaddrs(ifaddr);
}

/**
 * Receives broadcast messages from other services.
 * Simply logs the received message to the console.
 */
void receive_broadcasts(int sockfd) {
    char buffer[MAX_BUFFER_SIZE];
    sockaddr_in senderAddr = {};
    socklen_t senderLen = sizeof(senderAddr);

    // Check if there's data to read without blocking
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;  // Non-blocking, just check if there's data
    
    int ready = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
    if (ready < 0) {
        std::cerr << "Select failed: " << strerror(errno) << "\n";
        return;
    }
    
    // Nothing to read, return immediately
    if (ready == 0) {
        return;
    }

    // Read messages while there are any available
    while (true) {
        int bytesReceived = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE - 1, 0, 
                                     (sockaddr*)&senderAddr, &senderLen);
        if (bytesReceived < 0) {
            // EAGAIN or EWOULDBLOCK indicate no more data to read
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            std::cerr << "Error receiving broadcast: " << strerror(errno) << "\n";
            break;
        }
        
        // Null-terminate the received data to treat it as a string
        buffer[bytesReceived] = '\0';
        
        // Convert sender IP address to string
        char senderIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(senderAddr.sin_addr), senderIP, INET_ADDRSTRLEN);
        
        // Simply log that we received a message
        std::cout << "Received broadcast from " << senderIP << ": " << buffer << std::endl;
    }
}

/**
 * Main program loop that periodically announces our service presence and
 * continuously listens for broadcasts from other services.
 */
int main() {
    // Set up the receiver socket
    const int receiver_sockfd = setup_receiver_socket();
    if (receiver_sockfd < 0) {
        std::cerr << "Failed to set up receiver socket, exiting\n";
        return 1;
    }
    
    // Set up the broadcast socket
    const int broadcast_sockfd = setup_broadcast_socket();
    if (broadcast_sockfd < 0) {
        std::cerr << "Failed to set up broadcast socket, exiting\n";
        close(receiver_sockfd);
        return 1;
    }

    time_t last_broadcast_time = 0;
    
    while (true) {
        time_t current_time = time(NULL);
        
        // Check if it's time to broadcast our presence
        if (current_time - last_broadcast_time >= ANNOUNCE_INTERVAL) {
            broadcast_service_presence(broadcast_sockfd);
            last_broadcast_time = current_time;
        }
        
        // Check for incoming broadcasts
        receive_broadcasts(receiver_sockfd);
        
        // Sleep for a short time to avoid hogging CPU
        usleep(100000);  // 100ms
    }
    
    // Clean up sockets (this code will never be reached in this example)
    close(receiver_sockfd);
    close(broadcast_sockfd);
    return 0;
}