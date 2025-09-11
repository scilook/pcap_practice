CC = gcc
CFLAGS = #-fsanitize=address #-Wall -Wextra -Werror -std=c99
LDFLAGS = -lpcap

TARGET = demo_capture

SRC = demo_capture.c utils.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f *.o

fclean: clean
	rm -f $(TARGET) $(DEMO_TARGET)

re: fclean all

install-deps:
	sudo apt-get update
	sudo apt-get install libpcap-dev

install-deps-rpm:
	sudo yum install libpcap-devel || sudo dnf install libpcap-devel

run: $(TARGET)
	sudo ./$(TARGET)

debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

help:
	@echo "Available targets:"
	@echo "  all          		- Build the capture program (default)"
	@echo "  clean        		- Remove object files"
	@echo "  fclean       		- Force clean - remove all generated files"
	@echo "  re           		- Rebuild everything from scratch (fclean + all)"
	@echo "  install-deps 		- Install libpcap development package (Debian/Ubuntu)"
	@echo "  install-deps-rpm	- Install libpcap development package (RHEL/CentOS/Fedora)"
	@echo "  run          		- Build and run with sudo"
	@echo "  debug       		- Build with debug symbols"
	@echo "  help        		- Show this help message"

.PHONY: all clean fclean re install-deps install-deps-rpm run debug help