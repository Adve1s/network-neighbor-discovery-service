# Neighbor Discovery Service

A background service that discovers other devices running the same service on local networks, along with a CLI tool to retrieve the active neighbor list.

## Overview

This project implements:

1. A background service that:
   - Monitors all network interfaces on the device
   - Broadcasts its presence on all connected local networks
   - Discovers other devices running the same service
   - Maintains a list of active neighbors (devices seen in the last 30 seconds)

2. A CLI tool that:
   - Connects to the background service
   - Retrieves and displays the list of active neighbors

## Requirements

- Ubuntu LTS (tested on Ubuntu 22.04)
- g++ with C++17 support
- make

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Adve1s/network-neighbor-discovery-service.git
cd neighbor-discovery-service
```

2. Build the service and CLI tool:

```bash
make
```

This will create two executable files:
- `service` - The background discovery service
- `cli` - The command-line interface tool

## Usage

### Running the Service

Start the background service:

```bash
./service &
```

The service will:
- Detect all network interfaces
- Broadcast on all valid interfaces every 10 seconds
- Listen for broadcasts from other instances of the service
- Maintain a list of active neighbors (last seen < 30 seconds)
- Clean up inactive neighbors every 5 seconds

### Using the CLI Tool

While the service is running, use the CLI tool to view active neighbors:

```bash
./cli
```

This will display a list of all active neighbors with their IP and MAC addresses.

## Technical Details

- The service uses UDP broadcasts on port 60000 for neighbor discovery
- Communication between the service and CLI uses a Unix domain socket at `/tmp/neighbor_service.sock`
- The service handles dynamic IP address changes and multiple network interfaces
- Neighbors are considered active if they've been seen in the last 30 seconds

## Design Approach

### Architecture Decisions

1. **Non-blocking I/O**: The service uses non-blocking sockets to handle multiple network operations without requiring threads (which were prohibited by the task requirements).

2. **Robust Error Handling**: The service includes comprehensive error detection and recovery mechanisms, including socket recreation when errors exceed thresholds.

3. **Separation of Concerns**: The code is organized into distinct functional areas:
   - Network interface management
   - Socket and communication setup
   - Neighbor discovery and management
   - Message processing
   - Resource management

4. **Clean Resource Management**: The service properly handles termination signals (SIGINT, SIGTERM, SIGHUP) and performs cleanup of resources before exit.

### Key Implementation Details

1. **Subnet-based Neighbor Definition**: Neighbors are identified when they share the same IP subnet as one of our interfaces, following the task requirements.

2. **MAC Address Identification**: Devices are uniquely identified by MAC address rather than IP address to handle dynamic IP changes correctly.

3. **IP Change Detection**: The service can detect when a neighbor's IP address changes and update records accordingly.

4. **Conflict Detection**: The service monitors for potential IP conflicts (multiple devices claiming the same IP).

5. **Efficient Broadcasting**: To reduce network traffic, the service tracks which subnets it has already broadcast to in each cycle.

6. **Separate CLI Tool**: Following Unix philosophy, the neighbor list retrieval functionality is implemented as a separate tool that communicates with the main service.

## Testing

I tested this application using VirtualBox with multiple virtual machines:
- 3 Ubuntu VMs in various network configurations
- One VM configured with 2 network interfaces
- Different combinations of network visibility between VMs

While the task suggests libvirt/virt-manager for testing, VirtualBox also works well for creating the necessary test environment. The key is to ensure you have multiple VMs with configurable networking to test the discovery mechanism across different network configurations.

## Potential Problems and Solutions

During extensive testing, I identified several edge cases that could affect the service in specific network configurations. While the current implementation handles common scenarios correctly, these edge cases might require additional consideration in production environments.

### 1. Multiple Interfaces with Identical Subnets

**Problem:** When a device has two or more network interfaces connected to physically separate networks but configured with the same subnet (e.g., two separate 192.168.1.x networks), the service announces itself only on one of those interfaces. This happens because:
- The service tracks which subnets it has broadcast to using the `my_subnets` set
- The UDP socket is bound to INADDR_ANY, which causes the OS to select a single interface for outgoing broadcasts

**Impact:** Neighbors connected to the second physical network might not discover the service, even though they are on the same subnet.

**Solution:** Implement interface-specific socket binding by:
- Creating a socket for each network interface instead of a single shared socket
- Binding each socket to its specific interface IP address
- Using the appropriate socket when broadcasting to each interface

This would significantly increase code complexity by requiring socket-per-interface management, error handling, and a more complex socket selection mechanism, but would ensure proper network isolation.

### 2. Multiple IPs on Same Subnet

**Problem:** When a single interface has multiple IP addresses in the same subnet, the service broadcasts using only one of those IPs. This occurs because:
- The broadcast message contains only one source IP address
- The OS selects which source IP to use when sending from a multi-IP interface

**Impact:** Potential confusion when neighbors detect a device but see a different IP than expected.

**Solution:** Enumerate all IP addresses associated with each interface and send separate broadcasts for each IP-MAC combination. This would require modifications to the interface detection logic and more careful tracking of which IP-subnet combinations have been broadcast.

### 3. Cross-Subnet Broadcasts

**Problem:** In specific multi-interface setups where subnet addressing overlaps between physically separate networks, Layer 2 broadcasts might reach neighbors through the "wrong" interface.

**Impact:** Services might discover neighbors through network paths that don't actually provide connectivity, potentially causing application-level communication failures.

**Solution:** This would require the interface-specific socket implementation described in solution #1, combined with more strict validation of received messages based on which socket received them.

### Trade-offs Considered

I chose not to implement these solutions in the current version because:

1. The additional complexity would make the code significantly harder to maintain and test
2. These scenarios are relatively rare in most production environments
3. The core functionality works correctly for standard network configurations
4. Socket-per-interface management introduces additional failure modes that would require more complex error recovery

In a production environment, the decision to implement these solutions would depend on specific network requirements and the likelihood of encountering these edge cases.