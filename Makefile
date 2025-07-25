# Makefile for capture.c
# TCP packet capture and analysis tool using libpcap

# Compiler and flags
CC = gcc
CFLAGS = #-Wall -Wextra -Werror -std=c99
LDFLAGS = -lpcap

# Target executable
TARGET = capture
# Alternative target for demo version
DEMO_TARGET = demo_capture

# Source files
SRC = capture.c
DEMO_SRC = demo_capture.c

# Default target
all: $(TARGET)

# Build main capture program
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Build demo version if demo_capture.c exists
demo: $(DEMO_TARGET)

$(DEMO_TARGET): $(DEMO_SRC)
	$(CC) $(CFLAGS) -o $(DEMO_TARGET) $(DEMO_SRC) $(LDFLAGS)

# Clean built files
clean:
	rm -f *.o

# Force clean - remove all generated files
fclean: clean
	rm -f $(TARGET) $(DEMO_TARGET)

# Rebuild everything from scratch
re: fclean all

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install libpcap-dev

# Install dependencies (CentOS/RHEL/Fedora)
install-deps-rpm:
	sudo yum install libpcap-devel || sudo dnf install libpcap-devel

# Run with elevated privileges (required for packet capture)
run: $(TARGET)
	sudo ./$(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Help target
help:
	@echo "Available targets:"
	@echo "  all          		- Build the capture program (default)"
	@echo "  demo         		- Build the demo_capture program"
	@echo "  clean        		- Remove object files"
	@echo "  fclean       		- Force clean - remove all generated files"
	@echo "  re           		- Rebuild everything from scratch (fclean + all)"
	@echo "  install-deps 		- Install libpcap development package (Debian/Ubuntu)"
	@echo "  install-deps-rpm	- Install libpcap development package (RHEL/CentOS/Fedora)"
	@echo "  run          		- Build and run with sudo"
	@echo "  debug       		- Build with debug symbols"
	@echo "  help        		- Show this help message"

.PHONY: all demo clean fclean re install-deps install-deps-rpm run debug help