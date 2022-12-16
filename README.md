# Network Traffic Monitoring

1. -i Network interface name (e.g., eth0)
    With this argument you can choose the network interface where the traffic monitoring
    will take place. For instance the command `sudo ./pcap_ex -i eth0` asks the programm
    to monitor the "eth0" network adapter. You should use sudo for this action because only
    the root can access it. Otherwise an error like "You don't have permission to capture on 
    that device" will be raised. The output is being printed in the log.txt file.
2. -r Packet capture file name (e.g., test.pcap)
    This argument lets the program capture packets from a .pcap file. You can use it like
    `./pcap_ex -r test.pcap` , where test.pcap is the file were the capture took part.
    The output is being printed on the terminal.
3. -f Filter expression (e.g., port 8080)
    By using this argument you can filter the captured packets by comparing the filter port
    with the source port of the packets. You can use it like `./pcap.ex -f "port 8080" -r test.pcap` ,
    for capturing packets from a file or `sudo ./pcap.ex -f "port 8080" -i eth0` , 
    for capturing packets from a network adapter.
4. -h Help message

### NOTE:
    While capturing packets you can limit the packets to capture
    by changing the variable "packLimit", in the main function.
    Default value = 0(no limit)


gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0