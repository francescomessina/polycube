#! /bin/bash
# 	       		  	   	 	TOPOLOGY
#	   NS1 |									  | NS2
#              |           	 +------+	   		+------+		  |
#        veth1_|------veth1----m1|  r1  |p1-------------------p2|  r2  |m2----veth2-------|veth2_
#     10.0.1.1 |      10.0.1.254 +------+10.0.0.1	10.0.0.2+------+ 10.0.2.254	  |10.0.2.1
#              |               								  |
#
#

set -x

# Delete the router r1,r2 if already existed
polycubectl router del r1
polycubectl router del r2

for i in `seq 1 2`;
do
	sudo ip netns del ns${i} > /dev/null 2>&1	# remove ns if already existed
	sudo ip link del veth${i} > /dev/null 2>&1

	sudo ip netns add ns${i}
	sudo ip link add veth${i}_ type veth peer name veth${i}
	sudo ip link set veth${i}_ netns ns${i}
	sudo ip addr add 10.0.${i}.254/24 dev veth${i}
	sudo ip link set veth${i} up
	sudo ip netns exec ns${i} ip addr add 10.0.${i}.1/24 dev veth${i}_
	sudo ip netns exec ns${i} ip link set dev veth${i}_ up
	sudo ip netns exec ns${i} route add default gw 10.0.${i}.254 veth${i}_ 
done

# Create the router r1,r2
polycubectl router add r1
polycubectl router add r2

# Create mirror ports
polycubectl r1 ports add m1 mirror=veth1
polycubectl r2 ports add m2 mirror=veth2

# Create ports p1 and p2 and connect the 2 routers
polycubectl r1 ports add p1 ip=10.0.0.1 netmask=255.255.255.252
polycubectl r2 ports add p2 ip=10.0.0.2 netmask=255.255.255.252
polycubectl connect r1:p1 r2:p2

# Add static entries in the routing table of router r1 and r2 
polycubectl r1 route add 10.0.2.0 255.255.255.0 10.0.0.2
polycubectl r2 route add 10.0.1.0 255.255.255.0 10.0.0.1

# Ping
sudo ip netns exec ns1 ping 10.0.2.1 -c 3 -i 0.5
sudo ip netns exec ns2 ping 10.0.1.1 -c 3 -i 0.5

##########################################################################
# Here it is show how packets continue to pass even if polycube has problems
#polycubectl router del r1
#polycubectl router del r2
# Ping
#sudo ip netns exec ns1 ping 10.0.2.1 -c 3 -i 0.5
#sudo ip netns exec ns2 ping 10.0.1.1 -c 3 -i 0.5
##########################################################################

# Delete the router r1 and r2
polycubectl router del r1
polycubectl router del r2
# Remove ns1, ns2 and veth1, veth2
sudo ip netns del ns1
sudo ip netns del ns2
sudo ip link del veth1
sudo ip link del veth2

