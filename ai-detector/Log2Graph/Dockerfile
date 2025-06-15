FROM ubuntu:22.04

# Install build dependencies and download newer CMake
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install CMake 4.0.1
RUN wget https://github.com/Kitware/CMake/releases/download/v4.0.1/cmake-4.0.1-linux-x86_64.sh \
    && chmod +x cmake-4.0.1-linux-x86_64.sh \
    && ./cmake-4.0.1-linux-x86_64.sh --prefix=/usr/local --skip-license \
    && rm cmake-4.0.1-linux-x86_64.sh

# Verify CMake installation
RUN cmake --version

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make -j$(nproc)

# Set entrypoint
ENTRYPOINT ["./build/Log2Graph"]
