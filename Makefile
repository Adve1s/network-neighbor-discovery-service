# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++17 -Wall

# Targets
TARGET_SERVICE = service
TARGET_CLI = cli

# Source files
SRCS_SERVICE = service.cpp
SRCS_CLI = cli.cpp

# Build rules
all: $(TARGET_SERVICE) $(TARGET_CLI)

$(TARGET_SERVICE): $(SRCS_SERVICE)
	$(CXX) $(CXXFLAGS) $(SRCS_SERVICE) -o $(TARGET_SERVICE)

$(TARGET_CLI): $(SRCS_CLI)
	$(CXX) $(CXXFLAGS) $(SRCS_CLI) -o $(TARGET_CLI)

# Clean rule
clean:
	rm -f $(TARGET_SERVICE) $(TARGET_CLI)
