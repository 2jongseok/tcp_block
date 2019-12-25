all: tcp_block

tcp_block:
	g++ -o tcp_block tcp_block.cpp -lpcap

clean:
	rm -f tcp_block
