#!/bin/bash

#
# Shell script to verify the settings on the network, subnet, firewalls and routes.
#

network=stanford-odysseus-net
subNetwork=subnet1
firewallRule1=stanford-odysseus-net-allow-nat-vm-gcp-services
firewallRule2=stanford-odysseus-net-allow-nat-vm-ssh
firewallRule3=stanford-odysseus-net-allow-gcp-access-internal-vm-ssh
firewallRule4=stanford-odysseus-net-allow-dataproc
firewallRule5=stanford-odysseus-net-deny-nat-vm-ftp-dns-smb-ntp-pop-imap
routes=stanford-odysseus-net-nat-vm-route
project_id=$1
network_ip=$2

Usage()
{
        echo "Usage : ./ProgramName ProjectID Stanford_Network_IP"
}

project_id=$1
if [ $# -ne 2 ] ; then
        echo "Missing mandatory arguments"
        Usage
        exit 1
fi

if [ "$network_ip" == "" ] ; then
        echo "Stanford Network IP is missing"
        Usage
        exit 1
fi

gcloud compute networks list | egrep --word-regexp $network &> /dev/null
status=`echo $?`
if [[ "$status" -ne "0" ]] ; then
        echo "Network doesn't exist"
        exit 1
else 
	echo "Network $network exists"
fi

gcloud compute networks subnets list | egrep --word-regexp $subNetwork &> /dev/null
status=`echo $?`
if [[ "$status" -ne "0" ]] ; then
        echo "Subnetwork doesn't exist"
        exit 1
else 
	echo "Subnetwork $subNetwork exists"
fi

echo "---------------------------------------------------"

gcloud compute firewall-rules describe $firewallRule1 &> /dev/null
status=`echo $?`
if [[ "$status" -ne "0" ]]; then 
	echo "Firewall rule $firewallRule1 for ingress doesn't exist"
else 
	echo "Firewall rule $firewallRule1 for ingress exists"
	rules=$(gcloud compute firewall-rules list --format="table(network, sourceTags.list(), targetTags, 
	      allowed[].map().firewall_rule().list():label=ALLOW)" --filter="name=$firewallRule1" | grep -v NETWORK)
	net=$(echo $rules | awk '{print $1}')
	if [[ $net == "stanford-odysseus-net" ]]; then 
		echo "Network is stanford-odysseus-net"
	else
		echo "Found network $net"
		echo "Network is not stanford-odysseus-net"
	fi
	source_tag=$(echo $rules | awk '{print $2}')
        if [[ $source_tag == "gcp-access-internal-vm" ]] ; then
                echo "Source tag is gcp-access-internal-vm"
        else
		echo "Found source tag $source_tag"
                echo "Source tag is gcp-access-internal-vm"
        fi
	target=$(echo $rules | awk '{print $3}' | cut -d "'" -f 2)
	if [[ $target == "nat-vm" ]]; then
		echo "Target tag is nat-vm"
	else
		echo "Found target tag is $target"
		echo "Target tag is nat-vm"
	fi	
	echo "Allowed ports are tcp:443,tcp:3306,tcp:5432"
	opened_ports=( $(echo $rules | awk {'print $4'}))
	echo "Opened ports : $opened_ports"
		
	ports=( $(echo $rules | cut -d " " -f 8 | tr ',' ' '))
        for i in ${ports[@]}
        do
	if  [ $i == "tcp:443" ] || [ $i == "tcp:3306" ] || [ $i == "tcp:5432" ]; then
        	echo " $i is allowed"
	else
		echo " $i is not allowed"
        fi
        done
fi 

echo "---------------------------------------------------"

gcloud compute firewall-rules describe $firewallRule2 &> /dev/null
status=`echo $?`
if [[ "$status" -ne "0" ]]; then
        echo "Firewall rule $firewallRule2 for ingress doesn't exist"
else
        echo "Firewall rule $firewallRule2 for ingress exists"
        rules=$(gcloud compute firewall-rules list --format="table(network, sourceRanges.list(), targetTags,
              allowed[].map().firewall_rule().list():label=ALLOW)" --filter="name=$firewallRule2" | grep -v NETWORK)
        net=$(echo $rules | awk '{print $1}')
        if [[ $net == "stanford-odysseus-net" ]]; then
                echo "Network is stanford-odysseus-net"
        else
                echo "Found network $net"
                echo "Network is not stanford-odysseus-net"
        fi
        source_ip=$(echo $rules | awk '{print $2}')
        if [[ $source_ip == "$network_ip" ]] ; then
                echo "Found Network IP $network_ip"
        else
                echo "Unable to find Network IP $network_ip"
        fi
	target=$(echo $rules | awk '{print $3}' | cut -d "'" -f2)
        if [[ $target == "nat-vm" ]]; then
                echo "Target tag is $target"
        else
		echo "Found target tag $target"
                echo "Target tag is not nat-vm"
        fi

        echo "Allowed ports are tcp:22"
	opened_ports=( $(echo $rules | awk {'print $4'} ))
        echo "Opened ports : $opened_ports"

        ports=( $(echo $rules | cut -d " " -f 8 | tr ',' ' ') )
        for i in ${ports[@]}
        do
        if  [ $i == "tcp:22" ]; then
                echo " $i is allowed"
	else
                echo " $i is not allowed"
        fi
        done
fi

echo "---------------------------------------------------"

gcloud compute firewall-rules describe $firewallRule3 &> /dev/null
status=`echo $?`
if [[ "$status" -ne "0" ]]; then
	echo "Firewall rule $firewallRule3 for ingress doesn't exist"
else
	echo "Firewall rule $firewallRule3 for ingress exists"
	rules=$(gcloud compute firewall-rules list --format="table(network, sourceTags.list(), targetTags,
              allowed[].map().firewall_rule().list():label=ALLOW)" --filter="name=$firewallRule3" | grep -v NETWORK)
	net=$(echo $rules | awk '{print $1}')
        if [[ $net == "stanford-odysseus-net" ]]; then
                echo "Network is stanford-odysseus-net"
        else
                echo "Found network $net"
                echo "Network is not stanford-odysseus-net"
	fi
	source_tag=$(echo $rules | awk '{print $2}')
        if [[ $source_tag == "nat-vm" ]] ; then
                echo "Source tag is nat-vm"
        else
                echo "Found source tag $source_tag"
                echo "Source tag is nat-vm"
        fi
        target=$(echo $rules | awk '{print $3}' | cut -d "'" -f 2)
        if [[ $target == "gcp-access-internal-vm" ]]; then
                echo "Target tag is gcp-access-internal-vm"
        else
                echo "Found target tag is $target"
                echo "Target tag is gcp-access-internal-vm"
        fi

	echo "Allowed ports are tcp:22"
	opened_ports=( $(echo $rules | awk {'print $4'}))
        echo "Opened ports : $opened_ports"

	ports=( $(echo $rules | cut -d " " -f 8 | tr ',' ' ') )
        for i in ${ports[@]}
        do
        if  [ $i == "tcp:22" ]; then
                echo " $i is allowed"
	else
                echo " $i is not allowed"
        fi
        done
fi

echo "---------------------------------------------------"

gcloud compute firewall-rules describe $firewallRule4 &> /dev/null
status=`echo $?`
if [[ "$status" -ne "0" ]]; then
        echo "Firewall rule $firewallRule4 for ingress doesn't exist"
else
        echo "Firewall rule $firewallRule4 for ingress exists"
	rules=$(gcloud compute firewall-rules list --format="table(network, sourceRanges.list(), targetServiceAccounts.list(),
              allowed[].map().firewall_rule().list():label=ALLOW)" --filter="name=$firewallRule4" | grep -v NETWORK)
	net=$(echo $rules | awk '{print $1}')
        if [[ $net == "stanford-odysseus-net" ]]; then
                echo "Network is stanford-odysseus-net"
        else
		echo "Found network $net"
        	echo "Network is not stanford-odysseus-net"
	fi
	source_range=$(echo $rules | awk '{print $2}')
        if [[ $source_range == "10.0.0.0/24" ]] ; then
                echo "Source Range is 10.0.0.0/24"
        else
		echo "Found source range $source_range"
        	echo "Source Range is not 10.0.0.0/24"
  	fi
	target=$(echo $rules | awk '{print $3}' | cut -d'@' -f1)
        if [[ $target == "service-dataproc" ]]; then
                echo "Target service account is service-dataproc"
        else 
		echo "Found target service account is $target"
        	echo "Target service account is not service-dataproc"
	fi

	echo "Allowed ports are tcp:1-65535,udp:1-65535"

	opened_ports=( $(echo $rules | awk '{print $4}' | cut -d " " -f 8 ))
        echo "Opened ports : $opened_ports"
	
	ports=( $(echo $rules | awk '{print $4}' | cut -d " " -f 8 | tr ',' ' ') )
        for i in ${ports[@]}
        do
        if  [ $i == "tcp:1-65535" ] || [ $i == "udp:1-65535" ]; then
                echo " $i is allowed"
        fi
        done
fi

echo "---------------------------------------------------"

gcloud compute firewall-rules describe $firewallRule5 &> /dev/null
status=`echo $?`
if [[ "$status" -ne "0" ]]; then
        echo "Firewall rule $firewallRule5 for egress doesn't exist"
else
        echo "Firewall rule $firewallRule5 for egress exists"
	rules=$(gcloud compute firewall-rules list --format="table(network, targetTags.list():label=TARGET_TAGS,
	      destinationRanges.list():label=DEST_RANGES, denied[].map().firewall_rule().list():label=DENY)" --filter="name=$firewallRule5" | grep -v NETWORK)
	net=$(echo $rules | awk '{print $1}')
        if [[ $net == "stanford-odysseus-net" ]]; then
                echo "Network is stanford-odysseus-net"
        else
                echo "Found network $net"
                echo "Network is not stanford-odysseus-net"
        fi
	target=$(echo $rules | awk {'print $2'})
        if [[ $target == "nat-vm" ]]; then
                echo "Target tag is nat-vm"
        else
		echo "Found target tag is $target"
                echo "Target tag is not nat-vm"
        fi
	dest_range=$(echo $rules | awk {'print $3'})
        if [[ $dest_range == "0.0.0.0/0" ]] ; then
                echo "Destination Range is 0.0.0.0/0"
        else
		echo "Destination range is $dest"
        fi
	
	denied_ports=( $(echo $rules | awk {'print $4'} ))
	echo "Denied ports : $denied_ports"	
        for i in ${ports[@]}
        do
        if  [ $i == "tcp:21" ] || [ $i == "tcp:53" ] ||  [ $i == "tcp:119" ] || [ $i == "tcp:445" ] || [ $i == "tcp:143" ] || [ $i == "tcp:993" ] || [ $i == "udp:53" ]; then
                echo "$i"
        fi
        done
fi

echo "---------------------------------------------------"

gcloud compute routes describe $routes &> /dev/null
status=`echo $?`
if [[ "$status" -ne "0" ]]; then
        echo "Router $routes doesn't exist"
else
	echo "Router $routes exists"
	routes=$(gcloud compute routes list --format="table(network, destRange, nextHopInstance, tags, priority )" --filter="name=$routes" | grep -v NETWORK)
	net=$(echo $rules | awk '{print $1}')
        if [[ $net == "stanford-odysseus-net" ]]; then
                echo "Network is stanford-odysseus-net"
        else
		echo "Found network is $net"
        	echo "Network is not stanford-odysseus-net"
	fi
	destRange=$(echo $routes | awk {'print $2'})
        if [[ $destRange == "0.0.0.0/0" ]] ; then
                echo "Destination IP Ranges is 0.0.0.0/0 "
        else
		echo "Found destination IP ranges is $destRange"
        	echo "Destination IP Ranges is not 0.0.0.0/0"
	fi
	nextHop=$(echo $routes | awk {'print $3'})
        if [[ $nextHop == "https://www.googleapis.com/compute/v1/projects/"$project_id"/zones/us-west1-a/instances/nat-vm" ]]; then
		echo "Next hop is nat-vm" 
        else
        	echo "Next Hop is $nextHop"
	fi
	tags=$(echo $routes | awk {'print $4'} | cut -d "'" -f 2)
        if [[ $tags == "gcp-access-internal-vm" ]] ; then
                echo "Instance tag is gcp-access-internal-vm"
        else
		echo "Found instance tag is $tags"
        	echo "Instance tag is not gcp-access-internal-vm"
	fi
	priority=$(echo $routes | awk {'print $5'})
        if [[ $priority == "500" ]] ; then
                echo "Priority set to 500"
        else
		echo "Found priotity is $priority"
        	echo "Priority is set to 500"
	fi
fi

exit 0

