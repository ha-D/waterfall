For the experimental setup to work, the decoy router code and client code must be using the same network card. For example, you could deploy the decoy router and client on two different VMs on the same machine.

For the purpose of the example, we'll assume we want to run the decoy router  on virtual machine `vm_d` and the client on virtual machine `vm_c`.
Both virtual machines have a network interface `en0` which are connected to an internal network allowing the virtual machines to communicate. Also, `vm_d` has a network interface `en1` which is connected to the internet. 

We'll setup the decoy router virtual machine so that it's two interfaces are bridged. This would give the client virtual machine access to the internet. We'll use `iptables` to intercept downstream packets on the decoy router.

# Deploying Experimental Decoy Router
### Creating the bridge
Run these commands with root access in the `vm_d` virtual machine to create the bridge
```
ifconfig en0 up
ifconfig en0 0.0.0.0
ifconfig en1 up
ifconfig en1 0.0.0.0

brctl addbr br0
brctl addif br0 en0 en1

dhclient br0
```

Download the code from [https://decoyrouting.works](https://decoyrouting.works).

```
pip install -r requirements.txt
```


We need to setup an `iptables` rule to capture the downstream packets from the overt. We'll assume we want to use Google as the overt destination. Find the `GoogleChannel` class in the file `client/channels.py`. The class has a `host` field (e.g. `172.217.17.32`) which is the overt address the client will use. Use the address to enter the following command

```
iptables -A FORWARD -i br0 -s 172.217.17.32 -j NFQUEUE --queue-num 1
```

As a side note, if you observe that the decoy is not intercepting the overt packets make sure you have the `br_netfilter` module loaded
```
modprobe br_netfilter
```
And also:
```
sysctl -w net.bridge.bridge-nf-call-iptables=1
sysctl -w net.ipv4.ip_forward=1
```

Everything is now ready to run the decoy code
```
cd decoy
python capturepackets.py
```

# Running the client
Download the code in the client virtual machine and install the Python dependencies  as explained above.

The client is using Google as an overt destination by default, if you wish to change this, you can do so by changing line `465` of `client/client.py`.

You will need to install `phantomjs` on the client virtual machine. Make sure it is installed and works before running the client.

Run the client
```
cd client
python client.py
```

The client's SOCKS server is running on port `2020`. You may use a browser or http client (e.g. curl) to connect and request an overt website.