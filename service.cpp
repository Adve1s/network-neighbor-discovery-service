#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>

// Configuration settings
#define BROADCAST_PORT 60000  // Port used for service discovery
#define ANNOUNCE_INTERVAL 10  // Time between broadcasts (seconds)

/**
 * Determines if a network interface can be used for broadcasting.
 * Checks for necessary properties like broadcast capability and non-loopback.
 */
bool is_valid_interface(ifaddrs* ifa) {
    return (ifa->ifa_addr != nullptr && 
            ifa->ifa_broadaddr != nullptr && 
            !(ifa->ifa_flags & IFF_LOOPBACK) && 
            (ifa->ifa_flags & IFF_BROADCAST));
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
bool send_broadcast(const std::string& broadcast_ip, const std::string& local_ip, const std::string& mac_address) {
    // Create a UDP socket for broadcasting
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Socket creation failed: " << strerror(errno) << "\n";
        return false;
    }

    // Enable broadcasting on this socket
    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0) {
        std::cerr << "Setting broadcast option failed: " << strerror(errno) << "\n";
        close(sockfd);
        return false;
    }

    // Set up the broadcast address structure
    sockaddr_in broadcastAddr = {};
    broadcastAddr.sin_family = AF_INET;
    broadcastAddr.sin_port = htons(BROADCAST_PORT);
    if (inet_pton(AF_INET, broadcast_ip.c_str(), &broadcastAddr.sin_addr) <= 0) {
        std::cerr << "Invalid broadcast address: " << broadcast_ip << "\n";
        close(sockfd);
        return false;
    }

    // Format the message with identifying information
    // The receiving function will add a timestamp when received
    std::string message = "NEIGHBOR " + local_ip + " " + mac_address;

    // Send the broadcast packet
    if (sendto(sockfd, message.c_str(), message.size(), 0, 
              (sockaddr*)&broadcastAddr, sizeof(broadcastAddr)) < 0) {
        std::cerr << "Broadcast send failed: " << strerror(errno) << "\n";
        close(sockfd);
        return false;
    }

    close(sockfd);
    return true;
}

/**
 * Main discovery function that announces our service on all network interfaces.
 * Iterates through network interfaces and broadcasts on each valid one.
 */
void broadcast_service_presence() {
    // Get a list of all network interfaces on this device
    ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get network interfaces: " << strerror(errno) << "\n";
        return;
    }
    
    // Check each interface
    for (ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        // Skip interfaces that aren't suitable for broadcasting
        if (!is_valid_interface(ifa)) {
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
        if (!send_broadcast(broadcast_ip, local_ip, mac_address)) {
            std::cerr << "Failed to send broadcast on interface " << ifa->ifa_name << "\n";
        }
    }
    
    // Free the memory allocated by getifaddrs
    freeifaddrs(ifaddr);
}

/**
 * Main program loop that periodically announces our service presence.
 */
int main() {
    while (true) {
        broadcast_service_presence();
        sleep(ANNOUNCE_INTERVAL);
    }
    return 0;
}