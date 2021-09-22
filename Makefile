all: pcap-test

pcap-test: print.o  main.o
	g++ -o pcap-test print.o main.o -lpcap

main.o: print.h main.c

print.o: print.h print.c

clean:
	rm -f pcap-test *.o
