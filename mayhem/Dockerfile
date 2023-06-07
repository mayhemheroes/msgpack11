# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake

## Add source code to the build stage.
ADD . /src

## Build
WORKDIR /src/build
RUN cmake -DCMAKE_BUILD_TYPE=Debug -DMSGPACK11_BUILD_TESTS=OFF -DMSGPACK11_BUILD_FUZZER=ON .. && make -j$(nproc)

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /src/build/mayhem/fuzz_pack /fuzz_pack
COPY --from=builder /src/mayhem/testsuite /testsuite

# Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_pack
