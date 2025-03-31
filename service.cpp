#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <fcntl.h>
#include <ctime>
#include <unordered_set>
#include <unordered_map>

// Configuration settings
#define BROADCAST_PORT 60000  // Port used for service discovery
#define ANNOUNCE_INTERVAL 10  // Time between broadcasts (seconds)
#define CLEANUP_INTERVAL 5    // Time between neighbor removals
#define MAX_BUFFER_SIZE 1024  // Maximum size of the receive buffer

// Neighbor information
struct Neighbor {
    std::string ip_address;
    std::string mac_address;
    time_t last_seen;
};

// Data structures used for neighbor communication
std::unordered_set<std::string> used_broadcasts;        // Used to avoid sending double messages
std::unordered_set<std::string> my_local_ips;           // Used to ignore own incoming messages
std::unordered_map<std::string, Neighbor> neighbors;    // Key: MAC address, Value: Neighbor struct
std::unordered_map<std::string, int> ip_usage_count;    // Track how many devices use each IP

/**
 * Returns a formatted string of the current time (HH:MM:SS)
 */
std::string get_current_time_str() {
    // Get current time as time_t value
    std::time_t now = std::time(nullptr);
    
    // Buffer to hold the formatted time string
    char time_str[9]; // Size 9 for HH:MM:SS + null terminator
    
    // Format time using strftime - converts to local time and formats as HH:MM:SS
    std::strftime(time_str, sizeof(time_str), "%H:%M:%S", std::localtime(&now));
    
    // Convert char array to string and return
    return std::string(time_str);
}

//Log message severity levels
enum LogLevel { INFO, WARN, ERROR };

/**
 * Logs a message with timestamp and severity level
 */
void log_message(LogLevel level, const std::string& message) {
    // Convert enum level to a readable string
    std::string level_str;
    switch (level) {
        case INFO:  level_str = "INFO"; break;
        case WARN:  level_str = "WARN"; break;
        case ERROR: level_str = "ERROR"; break;
    }
    
    // Format the log entry
    std::string log_entry = get_current_time_str() + ": " + level_str + ": " + message;
    
    // Output to appropriate stream based on severity
    if (level == INFO) {
        std::cout << log_entry << std::endl;
    } else {
        std::cerr << log_entry << std::endl;
    }
}

/**
 * Sets up a UDP socket to listen for incoming broadcasts on the specified port.
 * The socket is configured to be non-blocking.
 */
int setup_receiver_socket() {
    // Create a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_message(ERROR, "Receiver socket creation failed: " + std::string(strerror(errno)));
        return -1;
    }

    // Set the socket to non-blocking mode
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        log_message(ERROR, "Failed to get socket flags: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }
    
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_message(ERROR, "Failed to set socket non-blocking: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }

    // Allow multiple sockets to use the same port
    int reuseAddr = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr)) < 0) {
        log_message(ERROR, "Failed to set SO_REUSEADDR: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }

    // Add SO_REUSEPORT option
    int reusePort = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reusePort, sizeof(reusePort)) < 0) {
        log_message(ERROR, "Failed to set SO_REUSEPORT: " + std::string(strerror(errno)));
        // We can continue even if this fails, as SO_REUSEADDR is already set
        log_message(WARN, "Continuing without SO_REUSEPORT");
    }

    // Bind to the broadcast port on INADDR_ANY (listen on all interfaces)
    sockaddr_in receiverAddr = {};
    receiverAddr.sin_family = AF_INET;
    receiverAddr.sin_port = htons(BROADCAST_PORT);
    receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (sockaddr*)&receiverAddr, sizeof(receiverAddr)) < 0) {
        log_message(ERROR, "Bind to broadcast port failed: " + std::string(strerror(errno)));
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
        log_message(ERROR, "Broadcast socket creation failed: " + std::string(strerror(errno)));
        return -1;
    }

    // Enable broadcasting on this socket
    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0) {
        log_message(ERROR, "Setting broadcast option failed: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * Determines if a network interface can be used for broadcasting.
 * Checks for necessary properties like broadcast capability and non-loopback.
 */
bool is_valid_interface(const ifaddrs* ifa) {
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
 * Logs information about all valid network interfaces
 */
void log_interfaces() {
    ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != -1) {
        int valid_interface_count = 0;
        log_message(INFO, "Network interfaces detected:");
        
        for (ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (is_valid_interface(ifa)) {
                std::string local_ip, broadcast_ip;
                if (extract_ip_addresses(ifa, local_ip, broadcast_ip)) {
                    valid_interface_count++;
                    log_message(INFO, "  Interface: " + std::string(ifa->ifa_name) + 
                               ", IP: " + local_ip + 
                               ", Broadcast: " + broadcast_ip);
                }
            }
        }
        
        log_message(INFO, "Total valid interfaces for broadcasting: " + std::to_string(valid_interface_count));
        freeifaddrs(ifaddr);
    } else {
        log_message(ERROR, "Failed to get network interfaces: " + std::string(strerror(errno)));
    }
}

/**
 * Sends a UDP broadcast message to announce this service on the network.
 * The message includes the local IP and MAC address for identification.
 */
bool send_broadcast(const int sockfd, const std::string& broadcast_ip, const std::string& local_ip, const std::string& mac_address) {
    // Set up the broadcast address structure
    sockaddr_in broadcastAddr = {};
    broadcastAddr.sin_family = AF_INET;
    broadcastAddr.sin_port = htons(BROADCAST_PORT);
    if (inet_pton(AF_INET, broadcast_ip.c_str(), &broadcastAddr.sin_addr) <= 0) {
        log_message(ERROR, "Invalid broadcast address: " + broadcast_ip);
        return false;
    }

    // Format the message with identifying information
    // The receiving function will add a timestamp when received
    std::string message = "NEIGHBOR " + local_ip + " " + mac_address;

    // Send the broadcast packet
    if (sendto(sockfd, message.c_str(), message.size(), 0, 
              (sockaddr*)&broadcastAddr, sizeof(broadcastAddr)) < 0) {
        log_message(ERROR, "Broadcast send failed: " + std::string(strerror(errno)));
        return false;
    }
    return true;
}

/**
 * Main discovery function that announces our service on all network interfaces.
 * Iterates through network interfaces and broadcasts on each valid one.
 */
void broadcast_service_presence(const int broadcast_sockfd) {
    // Get a list of all network interfaces on this device
    ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
        log_message(ERROR, "Failed to get network interfaces: " + std::string(strerror(errno)));
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
            log_message(ERROR, "Failed to extract IP addresses for interface " + std::string(ifa->ifa_name));
            continue;
        }

        my_local_ips.insert(local_ip);
            
        // Get the MAC address for identification
        std::string mac_address;
        if (!get_mac_address(ifa->ifa_name, mac_address)) {
            log_message(ERROR, "Failed to get MAC address for interface " + std::string(ifa->ifa_name));
            continue;
        }
        
        // Skip if we've already broadcast to this network in this cycle
        if (used_broadcasts.find(broadcast_ip) != used_broadcasts.end()) {
            continue;
        }
        used_broadcasts.insert(broadcast_ip);  // Mark this broadcast address as used

        // Announce our presence on this interface
        if (!send_broadcast(broadcast_sockfd,broadcast_ip, local_ip, mac_address)) {
            log_message(ERROR, "Failed to send broadcast on interface " + std::string(ifa->ifa_name));
        }
    }
    
    // Free the memory allocated by getifaddrs
    freeifaddrs(ifaddr);
}

/**
 * Adds a new neighbor or updates an existing one
 */
void add_or_update_neighbor(const std::string& message_ip, const std::string& message_mac) {
    time_t current_time = time(NULL);
    
    // Check if we already have a neighbor with this MAC
    auto it = neighbors.find(message_mac);
    
    // New neighbor (MAC not found)
    if (it == neighbors.end()) {
        // Add to map
        neighbors[message_mac] = {message_ip, message_mac, current_time};

        log_message(INFO,"Added new neighbor: IP=" + message_ip + ", MAC=" + message_mac);

        // Increment IP usage count
        ip_usage_count[message_ip]++;

        // Check for IP conflict (multiple devices using same IP)
        // This could indicate IP spoofing or network misconfiguration
        if (ip_usage_count[message_ip] > 1) {
            log_message(WARN, "IP conflict detected: " + message_ip + " is used by " + 
                        std::to_string(ip_usage_count[message_ip]) + " devices");
        }

    }else{    
        // Check if IP changed
        if (it->second.ip_address != message_ip) {
            log_message(INFO, "IP change detected for MAC " + message_mac + ": " 
                + it->second.ip_address + " -> " + message_ip);
            
            // Decrement old IP usage count
            ip_usage_count[it->second.ip_address]--;
            
            // Update the IP
            it->second.ip_address = message_ip;
            
            // Increment new IP usage count
            ip_usage_count[message_ip]++;
            
            // Check for IP conflict with new IP
            if (ip_usage_count[message_ip] > 1) {
                log_message(WARN, "IP conflict detected: " + message_ip + " is used by " + 
                            std::to_string(ip_usage_count[message_ip]) + " devices");
            }
        }
        
        // Always update timestamp
        it->second.last_seen = current_time;
    }
}

/**
 * Removes neighbors that haven't been seen in the last 30 seconds
 */
void remove_inactive_neighbors() {
    time_t current_time = time(NULL);
    
    // Iterate through the neighbors map and remove inactive entries
    auto it = neighbors.begin();
    while (it != neighbors.end()) {
        // Check if this neighbor hasn't been seen for 30 seconds
        if (current_time - it->second.last_seen > 30) {
            log_message(INFO, "Removing inactive neighbor: IP=" + it->second.ip_address + 
                       ", MAC=" + it->second.mac_address);
            
            // Decrement IP usage count
            ip_usage_count[it->second.ip_address]--;

            // Erase returns the next valid iterator
            it = neighbors.erase(it);
        } else {
            // Move to next entry
            ++it;
        }
    }
}

/**
 * Validates a MAC address string format.
 * Checks that the string matches the standard colon-separated MAC address format.
 */
bool validate_mac_address(const std::string& mac) {
    // Check for correct length (17 characters for XX:XX:XX:XX:XX:XX)
    if (mac.length() != 17) return false;
    
    // Check that colon separators are in the correct positions
    if (mac[2] != ':' || mac[5] != ':' || mac[8] != ':' || 
        mac[11] != ':' || mac[14] != ':') {
        return false;
    }
    
    // Verify all other characters are valid hexadecimal digits
    for (int i = 0; i < 17; i++) {
        // Skip the colon positions
        if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) continue;
        
        // Check that character is a valid hex digit
        if (!isxdigit(mac[i])) return false;
    }
    
    return true;
}

/**
 * Processes received broadcast messages.
 * Validates format, message type, and checks sender IP against message IP.
 */
bool process_message(const std::string& sender_ip, const std::string& message) {
    // Parse the message into its component parts
    std::istringstream iss(message);
    std::string message_type, message_ip, message_mac;
    
    // Extract the three expected parts
    if (!(iss >> message_type >> message_ip >> message_mac)) {
        log_message(ERROR, "Invalid message format: " + message);
        return false;
    }
    
    // Check if this is a NEIGHBOR announcement
    if (message_type != "NEIGHBOR") {
        log_message(ERROR, "Unknown message type: " + message_type);
        return false;
    }

    // Validate IP address format
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, message_ip.c_str(), &(sa.sin_addr)) != 1) {
        log_message(ERROR, "Invalid IP address format: " + message_ip);
        return false;
    }
    
    // Validate MAC address format
    if (!validate_mac_address(message_mac)) {
        log_message(ERROR, "Invalid MAC address format: " + message_mac);
        return false;
    }

    // Compare sender IP with message IP
    if (message_ip != sender_ip) {
        log_message(WARN, "IP mismatch - Message claims " + message_ip 
            + " but packet came from " + sender_ip);
    }

    // Skip adding ourselves as a neighbor if the message IP is one of our own
    if (my_local_ips.find(message_ip) != my_local_ips.end()) {
        return true;
    }

    // Pass validated neighbor information for tracking
    add_or_update_neighbor(message_ip, message_mac);
    return true;
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
        log_message(ERROR, "Select failed: " + std::string(strerror(errno)));
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
            log_message(ERROR, "While receiving broadcast: " + std::string(strerror(errno)));
            break;
        }
        
        // Null-terminate the received data to treat it as a string
        buffer[bytesReceived] = '\0';
        
        // Convert sender IP address to string
        char senderIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(senderAddr.sin_addr), senderIP, INET_ADDRSTRLEN);

        if (!process_message(senderIP,buffer)) {
            log_message(ERROR, "Failed to process message : " + std::string(buffer));
            continue;
        }
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
        log_message(ERROR, "Failed to set up receiver socket, exiting");
        return 1;
    }
    log_message(INFO, "Receiver socket successfully initialized");
    
    // Set up the broadcast socket
    const int broadcast_sockfd = setup_broadcast_socket();
    if (broadcast_sockfd < 0) {
        log_message(ERROR, "Failed to set up broadcast socket, exiting");
        close(receiver_sockfd);
        return 1;
    }

    log_message(INFO, "Broadcast socket successfully initialized");
    log_message(INFO, "Initializing neighbor discovery service...");
    log_interfaces();
    log_message(INFO, "Neighbor discovery service successfully started");

    time_t last_broadcast_time = 0;
    time_t last_cleanup_time = 0;

    while (true) {
        time_t current_time = time(NULL);
        
        // Check if it's time to broadcast our presence
        if (current_time - last_broadcast_time >= ANNOUNCE_INTERVAL) {
            used_broadcasts.clear();
            my_local_ips.clear();
            broadcast_service_presence(broadcast_sockfd);
            last_broadcast_time = current_time;
        }

        // Check if it's time to clean up inactive neighbors
        if (current_time - last_cleanup_time >= CLEANUP_INTERVAL) {
            remove_inactive_neighbors();
            last_cleanup_time = current_time;
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