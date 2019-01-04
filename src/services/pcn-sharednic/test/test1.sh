set -x

# delete instance sn1 if already existed
polycubectl sharednic del s1
# delete instance r1 if already existed
polycubectl router del r1
# delete instance n1 if already existed
polycubectl nat del n1


ip_wlan0=...
ip_nexthop=...
netmask=...
mac_wlan0=...

sudo ip netns del ns1
sudo ip link del veth1

sudo ip netns add ns1
sudo ip link add veth1 type veth peer name veth2
sudo ip link set veth1 netns ns1
sudo ip netns exec ns1 ifconfig veth1 10.0.0.1/24
sudo ip netns exec ns1 ip route add default via 10.0.0.2
sudo ifconfig veth2 hw ether AA:AA:AA:AA:AA:AA
sudo ifconfig veth2 10.0.0.2/24


# create instance of service sharednic
polycubectl sharednic add s1
# create instance of service router
polycubectl router add r1
# create instance of service nat
polycubectl nat add n1

# add ports to router and nat (mirror port)
polycubectl router r1 ports add vth2 ip=10.0.0.2 netmask=255.255.255.0 mac=AA:AA:AA:AA:AA:AA peer=veth2

polycubectl router r1 ports add nat ip=$ip_wlan0 netmask=$netmask mac=$mac_wlan0
polycubectl nat n1 ports add router type=INTERNAL
polycubectl connect r1:nat n1:router

polycubectl router r1 route add 0.0.0.0 0.0.0.0 $ip_nexthop

# connect sharednic to wlan0
polycubectl connect s1:interface wlan0

polycubectl nat n1 ports add sharednic type=EXTERNAL ip=$ip_wlan0
polycubectl connect s1:polycube n1:sharednic

#polycubectl nat n1 ports add wl type=EXTERNAL ip=$ip_wlan0
#polycubectl connect n1:wl wlan0

# Enable masquerade
polycubectl n1 rule masquerade enable


