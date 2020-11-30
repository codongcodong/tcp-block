all: tcp-block

tcp-block: main.o tcpBlock.o mac.o ethhdr.o
	g++ -o tcp-block main.o tcpBlock.o mac.o ethhdr.o -lpcap

main.o: main.cpp
	g++ -Wall -c -o main.o main.cpp 

tcpBlock.o: tcpBlock.cpp tcpBlock.h
	g++ -Wall -c -o tcpBlock.o tcpBlock.cpp 

mac.o: mac.cpp mac.h
	g++ -Wall -c -o mac.o mac.cpp 

ethhdr.o: ethhdr.cpp ethhdr.h
	g++ -Wall -c -o ethhdr.o ethhdr.cpp 

clean:
	rm -f tcp-block *.o

