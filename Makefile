CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall

BIN = bin
SRC = src
TARGET = $(BIN)/exe_inspector
SRCS = $(SRC)/main.cpp

all: $(BIN) $(TARGET)

$(BIN):
	mkdir -p $(BIN)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -rf $(BIN)
