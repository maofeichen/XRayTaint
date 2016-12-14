# main : 
# 	g++ -o bin/xt_main src/xt_main.cpp src/xt_file.cpp -Iinclude/

TARGET = xt_main

CC := g++-4.9
# CC := g++
CFLAGS := -g -std=c++11
# CFLAGS := -g -std=c++0x
INC = -I include
DEBUG = -DEBUG

LINKER = g++-4.9 -o
# LINKER = g++ -o
LFLAGS = -g

# OBJS = xt_main.o xt_file.o
SRC_DIR := src
HEADER_DIR = include
BUILD_DIR := build
BIN_DIR = bin

SOURCES  := $(wildcard $(SRC_DIR)/*.cpp)
INCLUDES := $(wildcard $(HEADER_DIR)/*.h)
OBJECTS  := $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

$(BIN_DIR)/$(TARGET) : $(OBJECTS)
	@$(LINKER) $@ $(LFLAGS) $(OBJECTS)
	@echo "Linking complete!"

$(OBJECTS): $(BUILD_DIR)/%.o : $(SRC_DIR)/%.cpp
	@$(CC) $(CFLAGS) $(INC) $(DEBUG) -c $< -o $@
	@echo "Compiled "$<" successfully!"


# xt_main : $(OBJS)
# 	$(CC) -o bin/xt_main $(OBJS) -Iinclude

# xt_main.o : src/xt_main.cpp
# 	$(CC) -c src/xt_main.cpp -Iinclude

# xt_file.o : src/xt_file.cpp
# 	$(CC) -c src/xt_file.cpp -Iinclude

.PHONY : clean
clean:
	rm $(OBJECTS) $(BIN_DIR)/$(TARGET) #$(OBJS)