#! /bin/bash
# 	       		  	   				 TOPOLOGY
#
#        NS1 |	       	  	 +--------+		     		       +--------+			 | NS1
#            |          	 |        |		   OSPF      	       | router |			 |
#       veth1|--------------veth2| LINUX  |vboxnet0----------------------enp0s3|   VM   |veth2-------------------|veth1
# 10.0.0.1/24|        10.0.0.2/24|(quagga)|192.168.0.1/24   	 192.168.0.3/24|(quagga)|20.0.0.2/24	     	 |20.0.0.1/24
#            |             |	 |	  |	|			       +--------+			 |
#	     |		   |	 +--------+	|								 |
#	     |		   +---m2|   r1	  |m1---+							 	 |
#	     			 +--------+	
#
#          	      	        		       

set -x

# Delete the router r1,r2 if already existed
polycubectl router del r1
polycubectl router del r2

# remove old configurations
sudo ip netns del ns1
sudo ip netns del ns2
sudo ip link del veth1
sudo ip link del veth2

# configure quagga
#sudo systemctl start zebra.service
#sudo systemctl start ospfd.service

# add namespace and links
for i in `seq 1 1`;
do
	sudo ip netns add ns${i}
	sudo ip link add veth1 type veth peer name veth2
	sudo ip addr add 10.0.0.2/24 dev veth2
	sudo ip link set veth2 up
	sudo ip link set veth1 netns ns${i}
	sudo ip netns exec ns${i} ip addr add 10.0.0.1/24 dev veth1
	sudo ip netns exec ns${i} ip link set dev veth1 up
	sudo ip netns exec ns${i} route add default gw 10.0.0.2 veth1 
done

# Create the router r1
polycubectl router add r1

# Create mirror ports
polycubectl r1 ports add m1 mirror=vboxnet0
polycubectl r1 ports add m2 mirror=veth2

# Ping
sudo ip netns exec ns1 ping 20.0.0.1

##########################################################################
# Here it is show how packets continue to pass even if polycube has problems
#polycubectl router del r1
# Ping
#sudo ip netns exec ns1 ping 20.0.0.1 
##########################################################################

