default:
	gcc pcap_ex.c -o pcap_ex -lpcap

clean:
	rm -rf pcap_ex