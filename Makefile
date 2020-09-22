all: pcap-test

pcap-test: main.o
	g++ -o pcap-test main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp -lpcap

clean:
	rm -f pcap-test *.o

