default:
	gcc assign5.c -o assign5 -lpcap

test:
	gcc test.c -o test -lpcap

clean:
	rm -rf test
	rm -rf assign5