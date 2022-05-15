tcpdump -i eth0 tcp -w /app/target.pcap -c 100 dst 10.244.246.130

while true
do
	echo "Press [CTRL+C] to stop.."
	sleep 1
done