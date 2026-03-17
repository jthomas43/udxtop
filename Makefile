
all:
	gcc -g -Wall -Werror *.c -lpcap -lncursesw -o udxtop
	sudo setcap cap_net_raw,cap_net_admin+eip ./udxtop
