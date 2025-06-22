### OS-Level Intrusion Detection System for Linux

## Setup

You need gcc and the libnetfilter-queue library

```
sudo apt update
sudo apt install gcc
sudo apt install libnetfilter-queue-dev
```

To compile the code:

```
gcc -o os-ids main.c logger.c cidr_trie.c emerging_threats_updater.c suricata_parser.c -lnetfilter_queue
```

To run the OS-IDS:

```
sudo ./os-ids
```

## NFTABLES setup

> [!WARNING]
> Setup instructions below are no longer necessary! Running `sudo ./os-ids` will now also initialize the necessary `nftables` rules, required for the IDS. The sections below act as a bit of a run-down of what `nftables` and `iptables` achieves for our program.

### IPTABLES setup

Ofcourse running `sudo ./os-ids` now will do nothing, unless an NFQUEUE iptables rule is set up. Be cautious, because the `iptables` rule will most likely forward the traffic to some program (in our case the IDS). If no such program is running to accept the traffic, your rule will be forwarding IP packets into a black hole. You will lose connection to the internet (if accessing the machine remotely). Make sure the rule has a failsafe, or that a service fit for accepting `NFQUEUE` traffic is running.

Outgoing traffic:

```
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0nfta
```

Incoming traffic:

```
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
```

Host IP neither source nor target (e. g. routers):

```
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

To run the OS-IDS:

```
sudo ./os-ids
```

### NFTABLES setup (modern)

Below is an `nftables` setup for ALL (input/output/forward) the rules (usually iptables commands call the nftables backend, but these commands are more explicit).

```
sudo nft add table inet myfilter

sudo nft add chain inet myfilter input  { type filter hook input priority 0 \; }
sudo nft add chain inet myfilter output { type filter hook output priority 0 \; }
sudo nft add chain inet myfilter forward { type filter hook forward priority 0 \; }

sudo nft add rule inet myfilter input queue num 0
sudo nft add rule inet myfilter output queue num 0
sudo nft add rule inet myfilter forward queue num 0
```

To get rid of the rules:

```
sudo nft flush ruleset
```
