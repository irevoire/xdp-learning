## To use the xdp-loader you need to increase the ulimit to more than 1024.

```
% sudo su
# ulimit -l 1024
```


## To enable forwarding:
```
# sysctl -w net.ipv4.ip_forward=1
# sysctl -w net.ipv6.ip_forward=1
# #### disable ip table
# sysctl -w net.bridge.bridge-nf-call-iptables=0
# sysctl -w net.bridge.bridge-nf-call-arptables=0
```

