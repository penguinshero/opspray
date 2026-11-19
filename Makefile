BINARY_NAME=opspray
BUILD_DIR=bin

.PHONY: all build clean tidy

all: build

build:
	@mkdir -p $(BUILD_DIR)
	@go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) main.go

clean:
	@rm -rf $(BUILD_DIR)

tidy:
	@go mod tidy
