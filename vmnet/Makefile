CC=clang
CFLAGS=-Wall -Wextra -O2 -fblocks -mmacosx-version-min=13.0
OBJCFLAGS=$(CFLAGS) -fobjc-arc
LDFLAGS_HELPER=-framework vmnet

SRC_DIR=src
OBJ_DIR=build/obj
BIN_DIR=build

HELPER=$(BIN_DIR)/vmnet-helper

.PHONY: all clean

all: $(HELPER)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR)/vmnet_helper.o: $(SRC_DIR)/vmnet_helper.m $(SRC_DIR)/vmnet_proto.h | $(OBJ_DIR)
	$(CC) $(OBJCFLAGS) -c $< -o $@

$(HELPER): $(OBJ_DIR)/vmnet_helper.o | $(BIN_DIR)
	$(CC) $(OBJCFLAGS) $< $(LDFLAGS_HELPER) -o $@

clean:
	rm -rf build
