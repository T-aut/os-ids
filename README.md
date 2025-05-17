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
gcc -o os-ids main.c -lnetfilter_queue
```

Ofcourse running `sudo ./os-ids` now will do nothing, unless an NFQUEUE iptables rule is set up. Be cautious, because the `iptables` rule will most likely forward the traffic to some program (in our case the IDS). If no such program is running to accept the traffic, your rule will be forwarding IP packets into a black hole. You will lose connection to the internet (if accessing the machine remotely). Make sure the rule has a failsafe, or that a service fit for accepting `NFQUEUE` traffic is running.

Outgoing traffic:

```
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
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
