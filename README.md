
# udxtop

`iftop` clone for UDX streams: It lists all UDX streams on an interface and shows their throughput.


## build

```sh
# first install pcap and pcap header files for your system
# e.g. on ubuntu:
apt install pcap pcap-devel libncurses-dev
# build the binary
make
# run wihout root (Linux)
sudo setcap cap_net_raw,cap_net_admin+eip ./udxtop
```


## usage

live capture
```sh
# live capture on the first interface found, usually wifi or wired ethernet
udxtop

# live capture on specific interface
udxtop -i eth0

```

## controls

'q' to quit

