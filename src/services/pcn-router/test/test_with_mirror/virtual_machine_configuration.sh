#! /bin/bash
# 	       		  	   				 TOPOLOGY
#
#        NS1 |	       	  	 +--------+		     		       +--------+			 | NS1
#            |          	 |        |		   OSPF      	       | ROUTER |			 |
#       veth1|--------------veth2| LINUX  |vboxnet0----------------------enp0s3|   VM   |veth2-------------------|veth1
# 10.0.0.1/24|        10.0.0.2/24|(quagga)|192.168.0.1/24   	 192.168.0.3/24|(quagga)|20.0.0.2/24	     	 |20.0.0.1/24
#            |             |	 |	  |	|			       +--------+			 |
#	     |		   |	 +--------+	|								 |
#	     |		   +---m2|   r1	  |m1---+							 	 |
#	     			 +--------+	
#
#          	      	        		       
          	      	        		      
# remove old configurations
sudo ip netns del ns1
sudo ip link del veth1
sudo ip link del veth2

# add namespace and links
sudo ip netns add ns1
sudo ip link add veth1 type veth peer name veth2
sudo ip addr add 20.0.0.2/24 dev veth2
sudo ip link set veth2 up
sudo ip link set veth1 netns ns1
sudo ip netns exec ns1 ip addr add 20.0.0.1/24 dev veth1
sudo ip netns exec ns1 ip link set dev veth1 up
sudo ip netns exec ns1 ip route add default via 20.0.0.1


# configure quagga
#sudo systemctl start zebra.service
#sudo systemctl start ospfd.service
