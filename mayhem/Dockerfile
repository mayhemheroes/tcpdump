FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libpcap-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang

COPY . /repo
WORKDIR /repo
RUN ./configure --prefix=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_mask62plen.cpp -fsanitize=fuzzer,address -I /repo/ -L /repo/ -lnetdissect -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_mask62plen
