FROM alpine:3.20

# coreutils: GNU date supports %N (busybox date does not), so every capture
# (re)start gets a unique gateway-<nanoseconds>.pcap file name.
RUN apk add --no-cache tcpdump coreutils

# The capture command (interface, filter, output file) is set in docker-compose.yml.
CMD ["tcpdump", "--version"]
