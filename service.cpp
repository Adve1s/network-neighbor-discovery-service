#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <fcntl.h>
#include <ctime>
#include <unordered_set>
#include <unordered_map>
#include <csignal>

// Configuration settings
#define BROADCAST_PORT 60000   // Port used for service discovery
#define ANNOUNCE_INTERVAL 10   // Time between broadcasts (seconds)
#define CLEANUP_INTERVAL 5     // Time between neighbor removals
#define MAX_BUFFER_SIZE 1024   // Maximum size of the receive buffer
#define SOCKET_PATH "/tmp/neighbor_service.sock" // Unix socket for CLI communication
#define ERROR_THRESHOLD 3      // Number of consecutive errors before socket recreation
#define MAX_SOCKET_RECREATE_ATTEMPTS 5   // Number of attemts to recreate socket
#define SOCKET_RECREATE_BACKOFF_MS 1000  // Start with 1 second

volatile sig_atomic_t shutdown_requested = 0;    // Flag to indicate shutdown is requested

// Neighbor information
struct Neighbor {
    std::string ip_address;
    std::string mac_address;
    time_t last_seen;
};

// Data structures used for neighbor communication
std::unordered_set<std::string> my_subnets;        // Used to avoid sending double messages
std::unordered_set<std::string> my_local_ips;           // Used to ignore own incoming messages
std::unordered_map<std::string, Neighbor> neighbors;    // Key: MAC address, Value: Neighbor struct
std::unordered_map<std::string, int> ip_usage_count;    // Track how many devices use each IP
int udp_error_count = 0;  // Counter for UDP socket errors
int cli_error_count = 0;  // Counter for CLI socket errors

//------------------------------------------------------------------------------
// Utility and Helper Functions
//------------------------------------------------------------------------------

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
 * Sets a socket to non-blocking mode.
 * Uses fcntl to modify the socket's flags without affecting other settings.
 */
bool set_socket_nonblocking(int sockfd, const std::string& socket_name) {
    // Get current flags
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        log_message(ERROR, "Failed to get " + socket_name + " socket flags: " + std::string(strerror(errno)));
        return false;
    }
    
    // Set non-blocking flag without affecting other flags
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_message(ERROR, "Failed to set " + socket_name + " socket non-blocking: " + std::string(strerror(errno)));
        return false;
    }
    
    return true;
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
 * Calculates the subnet address from an IP address and netmask.
 * Performs a bitwise AND operation between the IP and netmask.
 */
std::string calculate_subnet(const sockaddr_in* ip_addr, const sockaddr_in* netmask) {
    // Perform the bitwise AND between IP and netmask
    in_addr subnet_addr;
    subnet_addr.s_addr = ip_addr->sin_addr.s_addr & netmask->sin_addr.s_addr;
    
    // Convert to string format
    char subnet_str[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &subnet_addr, subnet_str, INET_ADDRSTRLEN)) {
        return "";
    }
    
    return subnet_str;
}

//------------------------------------------------------------------------------
// Network Interface Management
//------------------------------------------------------------------------------

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
 * Gets the IP addresses and subnet associated with a network interface.
 */
bool extract_ip_addresses(const ifaddrs* ifa, std::string& local_ip, std::string& broadcast_ip, std::string& subnet) {
    // Convert to IPv4 address format
    const auto* addr = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
    const auto* broadcast = reinterpret_cast<const sockaddr_in*>(ifa->ifa_broadaddr);
    const auto* netmask = reinterpret_cast<const sockaddr_in*>(ifa->ifa_netmask);
    
    // Prepare buffers for the string versions of the addresses
    char local_ip_buf[INET_ADDRSTRLEN] = {};
    char broadcast_ip_buf[INET_ADDRSTRLEN] = {};
    
    // Convert the addresses and check for errors
    if (!inet_ntop(AF_INET, &addr->sin_addr, local_ip_buf, INET_ADDRSTRLEN) ||
        !inet_ntop(AF_INET, &broadcast->sin_addr, broadcast_ip_buf, INET_ADDRSTRLEN)) {
        return false;
    }
    
    // Calculate subnet from IP and netmask
    subnet = calculate_subnet(addr, netmask);
    if (subnet.empty()) {
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
                std::string local_ip, broadcast_ip, subnet;
                if (extract_ip_addresses(ifa, local_ip, broadcast_ip, subnet)) {
                    valid_interface_count++;
                    log_message(INFO, "  Interface: " + std::string(ifa->ifa_name) + 
                               ", IP: " + local_ip + 
                               ", Broadcast: " + broadcast_ip + 
                               ", Subnet: " + subnet);
                }
            }
        }
        
        log_message(INFO, "Total valid interfaces for broadcasting: " + std::to_string(valid_interface_count));
        freeifaddrs(ifaddr);
    } else {
        log_message(ERROR, "Failed to get network interfaces: " + std::string(strerror(errno)));
    }
}

//------------------------------------------------------------------------------
// Socket and Communication Setup
//------------------------------------------------------------------------------

/**
* Sets up a UDP socket to listen for incoming messages and send broadcasts.
* The socket is configured to be non-blocking with broadcast capability.
*/
int setup_udp_socket(int port) {
    // Create a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_message(ERROR, "Socket creation failed for port " + std::to_string(port) + ": " + std::string(strerror(errno)));
        return -1;
    }

    // Set the socket to non-blocking mode
    if (!set_socket_nonblocking(sockfd, "UDP")) {
        close(sockfd);
        return -1;
    }

    // Allow multiple sockets to use the same port
    int reuse_addr = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) < 0) {
        log_message(ERROR, "Failed to set SO_REUSEADDR: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }

    // Add SO_REUSEPORT option
    int reuse_port = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port)) < 0) {
        log_message(ERROR, "Failed to set SO_REUSEPORT: " + std::string(strerror(errno)));
        // We can continue even if this fails, as SO_REUSEADDR is already set
        log_message(WARN, "Continuing without SO_REUSEPORT");
    }

    // Enable broadcast
    int broadcast_enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        log_message(ERROR, "Setting broadcast option failed: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }

    // Bind to the specified port on INADDR_ANY (listen on all interfaces)
    sockaddr_in sock_addr = {};
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);
    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
        log_message(ERROR, "Bind to port " + std::to_string(port) + " failed: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }

    log_message(INFO, "UDP socket ready on port " + std::to_string(port) + " (broadcast enabled)");
    return sockfd;
}

/**
 * Sets up a Unix domain socket for CLI communication.
 * The socket is configured to be non-blocking and listening for connections.
 */
int setup_cli_socket() {
    // Remove any existing socket file
    unlink(SOCKET_PATH);
    
    // Create a Unix domain socket
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_message(ERROR, "CLI socket creation failed: " + std::string(strerror(errno)));
        return -1;
    }
    
    // Set up the server address
    sockaddr_un server_addr = {};
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);
    server_addr.sun_path[sizeof(server_addr.sun_path) - 1] = '\0';
    
    // Bind the socket to the path
    if (bind(sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message(ERROR, "CLI socket bind failed: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }
    
    // Set the socket to non-blocking mode
    if (!set_socket_nonblocking(sockfd, "CLI")) {
        close(sockfd);
        return -1;
    }
    
    // Start listening for connections
    if (listen(sockfd, 5) < 0) {
        log_message(ERROR, "CLI socket listen failed: " + std::string(strerror(errno)));
        close(sockfd);
        return -1;
    }
     
    // Set permissions to allow any user to connect to the socket
    chmod(SOCKET_PATH, 0600);
    
    log_message(INFO, "CLI communication socket initialized at " + std::string(SOCKET_PATH));
    return sockfd;
}

/**
 * Attempts to recreate a failed socket.
 */
bool recreate_socket(int socket_type, int& current_sockfd) {
    int try_num = 0;
    if (socket_type == 0) {  // UDP socket
        log_message(WARN, "UDP socket failed. Attempting to recreate...");
    } else {  // CLI socket
        log_message(WARN, "CLI socket failed. Attempting to recreate...");
    }
    while(try_num <MAX_SOCKET_RECREATE_ATTEMPTS){
        // Sleep for the backoff duration
        usleep(try_num*SOCKET_RECREATE_BACKOFF_MS*1000);
        
        // Count number of tries
        try_num++;

        // Close the existing socket if it's valid
        if (current_sockfd >= 0) {
            close(current_sockfd);
        }
                
        // Attempt to recreate the appropriate socket
        if (socket_type == 0) {  // UDP socket
            log_message(INFO, "Recreating UDP socket...");
            current_sockfd = setup_udp_socket(BROADCAST_PORT);
            if (current_sockfd >= 0) {
                udp_error_count = 0;  // Reset the error counter
                return true;
            }
        } else {  // CLI socket
            log_message(INFO, "Recreating CLI socket...");
            current_sockfd = setup_cli_socket();
            if (current_sockfd >= 0) {
                cli_error_count = 0;  // Reset the error counter
                return true;
            }
        }
        log_message(ERROR, "Recreation failed, attempts left: " + std::to_string(MAX_SOCKET_RECREATE_ATTEMPTS-try_num));
    }
    log_message(ERROR, "CRITICAL: Failed to recreate socket after multiple attempts. Service cannot function properly and is shutting down.");
    return false;
}

//------------------------------------------------------------------------------
// Neighbor Management
//------------------------------------------------------------------------------

/**
 * Checks for IP-related issues like conflicts and mismatches
 */
void check_ip_issues(const std::string& message_ip, const std::string& sender_ip) {
    // Check for IP conflict (multiple devices using same IP)
    if (ip_usage_count[message_ip] > 1) {
        log_message(WARN, "IP conflict detected: " + message_ip + " is used by " + 
                    std::to_string(ip_usage_count[message_ip]) + " devices");
    }

    // Compare sender IP with message IP
    if (message_ip != sender_ip) {
        log_message(WARN, "IP mismatch - Message claims " + message_ip 
            + " but packet came from " + sender_ip);
    }
}

/**
 * Adds a new neighbor or updates an existing one
 */
void add_or_update_neighbor(const std::string& message_ip, const std::string& message_mac , const std::string& sender_ip) {
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

        // Check for ip issues
        check_ip_issues(message_ip, sender_ip);

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
            
            // Check for ip issues
            check_ip_issues(message_ip, sender_ip);
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
 * Formats the current list of active neighbors into a human-readable string.
 * This formatted information is sent to CLI clients upon request.
 */
std::string format_neighbor_list() {
    std::string result;
    
    if (neighbors.empty()) {
        result = "No active neighbors found.\n";
    } else {
        result = "Active neighbors:\n";
        result += "----------------\n";
        
        for (const auto& pair : neighbors) {
            const Neighbor& neighbor = pair.second;
            result += "IP: " + neighbor.ip_address + " | MAC: " + neighbor.mac_address + "\n";
        }
    }
    
    return result;
}

//------------------------------------------------------------------------------
// Message Processing
//------------------------------------------------------------------------------

/**
 * Processes received broadcast messages.
 * Handles different message types: NEIGHBOR announcements and GET_NEIGHBORS requests.
 */
bool process_message(const std::string& sender_ip, const std::string& message) {
    // Parse the message into its component parts
    std::istringstream iss(message);
    std::string message_type, message_ip, message_mac, message_subnet;
    
    // Extract the three expected parts
    if (!(iss >> message_type >> message_ip >> message_mac >> message_subnet)) {
        log_message(ERROR, "Invalid message format: " + message);
        return false;
    }
    
    // Check if this is a NEIGHBOR announcement
    if (message_type != "NEIGHBOR") {
        log_message(ERROR, "Unknown message type: " + message_type);
        return false;
    }

    // Check if we share a subnet with this neighbor
    if (my_subnets.find(message_subnet) == my_subnets.end()) {
        log_message(ERROR, "Ignoring message from different subnet: " + message_subnet);
        return false;
    }

    // Validate IP address and subnet format
    sockaddr_in sa;
    if (inet_pton(AF_INET, message_ip.c_str(), &(sa.sin_addr)) != 1) {
        log_message(ERROR, "Invalid IP address format: " + message_ip);
        return false;
    }
    
    // Validate MAC address format
    if (!validate_mac_address(message_mac)) {
        log_message(ERROR, "Invalid MAC address format: " + message_mac);
        return false;
    }

    // Skip adding ourselves as a neighbor if the message IP is one of our own
    if (my_local_ips.find(message_ip) != my_local_ips.end()) {
        return true;
    }

    // Pass validated neighbor information for tracking
    add_or_update_neighbor(message_ip, message_mac, sender_ip);
    return true;
}

/**
 * Receives and processes messages on the given socket.
 * Handles both neighbor broadcasts and CLI requests.
 */
void receive_messages(int& sockfd) {
    char buffer[MAX_BUFFER_SIZE];
    sockaddr_in sender_addr = {};
    socklen_t sender_len = sizeof(sender_addr);

    // Check if there's data to read without blocking
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    
    timeval timeout;
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
        int bytes_received = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE - 1, 0, 
                                     (sockaddr*)&sender_addr, &sender_len);
        if (bytes_received < 0) {
            // EAGAIN or EWOULDBLOCK indicate no more data to read
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            log_message(ERROR, "While receiving message: " + std::string(strerror(errno)));
            break;
        }
        
        // Null-terminate the received data to treat it as a string
        buffer[bytes_received] = '\0';
        
        // Convert sender IP address to string
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sender_addr.sin_addr), sender_ip, INET_ADDRSTRLEN);

        if (!process_message(sender_ip,buffer)) {
            log_message(ERROR, "Failed to process message: " + std::string(buffer));
            continue;
        }
    }
}

/**
 * Sends a UDP broadcast message to announce this service on the network.
 * The message includes the local IP and MAC address for identification.
 */
bool send_broadcast(const int sockfd, const std::string& broadcast_ip, const std::string& local_ip, const std::string& mac_address, const std::string& subnet) {
    // Set up the broadcast address structure
    sockaddr_in broadcast_addr = {};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(BROADCAST_PORT);
    if (inet_pton(AF_INET, broadcast_ip.c_str(), &broadcast_addr.sin_addr) <= 0) {
        log_message(ERROR, "Invalid broadcast address: " + broadcast_ip);
        return false;
    }

    // Format the message with identifying information
    // The receiving function will add a timestamp when received
    std::string message = "NEIGHBOR " + local_ip + " " + mac_address+ " " + subnet;

    // Send the broadcast packet
    if (sendto(sockfd, message.c_str(), message.size(), 0, 
              (sockaddr*)&broadcast_addr, sizeof(broadcast_addr)) < 0) {
        log_message(ERROR, "Broadcast send failed: " + std::string(strerror(errno)));
        return false;
    }
    return true;
}

/**
 * Main discovery function that announces our service on all network interfaces.
 * Iterates through network interfaces and broadcasts on each valid one.
 */
void broadcast_service_presence(int& broadcast_sockfd) {
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
        std::string local_ip, broadcast_ip, subnet;
        if (!extract_ip_addresses(ifa, local_ip, broadcast_ip,subnet)) {
            log_message(ERROR, "Failed to extract IP addresses for interface " + std::string(ifa->ifa_name));
            continue;
        }
        
        // Track local IPs
        my_local_ips.insert(local_ip);
            
        // Get the MAC address for identification
        std::string mac_address;
        if (!get_mac_address(ifa->ifa_name, mac_address)) {
            log_message(ERROR, "Failed to get MAC address for interface " + std::string(ifa->ifa_name));
            continue;
        }
        
        // Skip if we've already broadcast to this subnet in this cycle
        if (my_subnets.find(subnet) != my_subnets.end()) {
            continue;
        }
        my_subnets.insert(subnet);  // Mark this subnet address as used

        // Announce our presence on this interface
        if (!send_broadcast(broadcast_sockfd,broadcast_ip, local_ip, mac_address, subnet)) {
            log_message(ERROR, "Failed to send broadcast on interface " + std::string(ifa->ifa_name));
            udp_error_count++;
            if (udp_error_count >= 2) { 
                if(!recreate_socket(0, broadcast_sockfd)){ // 0 indicates UDP socket
                    shutdown_requested = 1;
                };
            }
        }
    }
    
    // Free the memory allocated by getifaddrs
    freeifaddrs(ifaddr);
}

//------------------------------------------------------------------------------
// CLI Client Handling
//------------------------------------------------------------------------------

/**
 * Handles a connection from a CLI client.
 * Reads the command, validates it, and sends the neighbor list if the command is valid.
 */
void handle_cli_client(int client_fd) {
    // Set the socket to non-blocking mode
    if (!set_socket_nonblocking(client_fd, "client")) {
        close(client_fd);
        return;
    }
    
    // Buffer for receiving the command
    char buffer[MAX_BUFFER_SIZE];
    
    // Read the command from the client
    int bytes_read = read(client_fd, buffer, MAX_BUFFER_SIZE - 1);
    
    // Check if we successfully read anything
    if (bytes_read <= 0) {
        if (bytes_read < 0) {
            log_message(ERROR, "Error reading from client: " + std::string(strerror(errno)));
        }
        return; // No data or error, just close the connection
    }
    
    // Null-terminate the received data to treat it as a string
    buffer[bytes_read] = '\0';
    
    // Check if the command is GET_NEIGHBORS (uppercase for consistency with your style)
    if (std::string(buffer) != "GET_NEIGHBORS") {
        log_message(ERROR, "Received invalid command: " + std::string(buffer));
        return; // Invalid command, just close the connection
    }
    
    // Log the valid command received
    log_message(INFO, "CLI client requested neighbor list");

    // Format the neighbor list
    std::string response = format_neighbor_list();
    
    // Send the response to the client
    size_t total_sent = 0;
    const char* response_data = response.c_str();
    size_t response_len = response.length();
    
    while (total_sent < response_len) {
        int sent = write(client_fd, response_data + total_sent, response_len - total_sent);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket buffer full, try again shortly
                usleep(1000);
                continue;
            }
            log_message(ERROR, "Error sending to client: " + std::string(strerror(errno)));
            break;
        }
        total_sent += sent;
    }
}

/**
 * Checks for and handles incoming CLI client connections.
 * Uses non-blocking accept() to process connection requests without
 * blocking the main service loop.
 */
void check_cli_connections(int& cli_sockfd) {
    // Set up client address structure
    sockaddr_un client_addr = {};
    socklen_t client_len = sizeof(client_addr);
    
    // Try to accept a new connection
    int client_fd = accept(cli_sockfd, (sockaddr*)&client_addr, &client_len);

    if (client_fd > 0) {
        // Handle the client connection
        handle_cli_client(client_fd);
        close(client_fd);  // Close after handling
    } else if (client_fd < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        log_message(ERROR, "Accept failed: " + std::string(strerror(errno)));
        cli_error_count++; // Add counter here
        if (cli_error_count >= 3) {
            if(!recreate_socket(1, cli_sockfd)){ // 1 indicates CLI socket
                shutdown_requested = 1;
            };
        }
    }
}

//------------------------------------------------------------------------------
// Resource Management
//------------------------------------------------------------------------------

/**
 * Signal handler function for termination signals.
 * Sets a global flag to indicate shutdown was requested.
 */
void handle_termination(int signal) {
    // Set the flag to exit the main loop
    shutdown_requested = 1;
    
    // Log which signal was received
    std::string signal_name;
    switch (signal) {
        case SIGINT:  signal_name = "SIGINT"; break;
        case SIGTERM: signal_name = "SIGTERM"; break;
        case SIGHUP:  signal_name = "SIGHUP"; break;
        default:      signal_name = "Unknown Signal (" + std::to_string(signal) + ")"; break;
    }
    
    log_message(INFO, "Received " + signal_name + " signal, shutting down...");
}

/**
 * Sets up signal handlers for common termination signals.
 * This allows the program to perform cleanup when terminated.
 */
void setup_signal_handlers() {
    // Register the same handler for multiple signals
    struct sigaction sa = {};
    sa.sa_handler = handle_termination;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    // Register for common termination signals
    sigaction(SIGINT, &sa, NULL);  // Ctrl+C
    sigaction(SIGTERM, &sa, NULL); // kill command
    sigaction(SIGHUP, &sa, NULL);  // Terminal closed
    
    log_message(INFO, "Signal handlers registered for graceful shutdown");
}

/**
 * Performs cleanup tasks before program exit.
 * Closes open sockets and removes the Unix socket file.
 */
void cleanup_resources(int service_sockfd, int cli_sockfd) {
    // Close the sockets
    if (service_sockfd >= 0) {
        close(service_sockfd);
    }
    
    if (cli_sockfd >= 0) {
        close(cli_sockfd);
    }
    
    // Remove the Unix socket file
    unlink(SOCKET_PATH);
    
    log_message(INFO, "Resources cleaned up, service terminated");
}

//------------------------------------------------------------------------------
// Main Function
//------------------------------------------------------------------------------

/**
 * Main program loop that periodically announces our service presence and
 * continuously listens for broadcasts from other services.
 */
int main() {
    // Set up signal handlers
    setup_signal_handlers();

    // Set up the service socket
    int service_sockfd = setup_udp_socket(BROADCAST_PORT);
    if (service_sockfd < 0) {
        if(!recreate_socket(0, service_sockfd)){ // 0 indicates UDP socket
            return 1;
        };
    }
    

    // Set up the service socket
    int cli_sockfd = setup_cli_socket();
    if (cli_sockfd < 0) {
        if(!recreate_socket(1, cli_sockfd)){ // 1 indicates CLI socket
            close(service_sockfd);
            return 1;
        };
    }

    log_message(INFO, "Initializing neighbor discovery service...");
    log_interfaces();
    log_message(INFO, "Neighbor discovery service successfully started");

    time_t last_broadcast_time = 0;
    time_t last_cleanup_time = 0;

    while (!shutdown_requested) {
        time_t current_time = time(NULL);
        
        // Check if it's time to broadcast our presence
        if (current_time - last_broadcast_time >= ANNOUNCE_INTERVAL) {
            my_subnets.clear();
            my_local_ips.clear();
            broadcast_service_presence(service_sockfd);
            last_broadcast_time = current_time;
        }

        // Check if it's time to clean up inactive neighbors
        if (current_time - last_cleanup_time >= CLEANUP_INTERVAL) {
            remove_inactive_neighbors();
            last_cleanup_time = current_time;
        }
        
        // Check for incoming broadcasts
        receive_messages(service_sockfd);

        // Check for CLI client connections
        check_cli_connections(cli_sockfd);
        
        // Sleep for a short time to avoid hogging CPU
        usleep(100000);  // 100ms
    }

    // Clean up resources when we exit the loop
    cleanup_resources(service_sockfd, cli_sockfd);

    return 0;
}