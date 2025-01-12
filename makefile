CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap -lpthread

TARGET = airodump
SRCS = airodump.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	make test-clean

test-setup:
	sudo modprobe mac80211_hwsim [radios=2]

test-setup-clean:
	sudo modprobe mac80211_hwsim -r

test-replay:
	sudo timeout 30 dot11replay -i wlan1 airodump.pcap &
	sudo timeout 30 ./${TARGET} wlan1

test-replay-file:
	sudo timeout 30 dot11replay -i wlan1 airodump.pcap &
	sudo timeout 30 ./${TARGET} wlan1 -t &
	sleep 2 &
	sudo timeout 30 tail -f airodump_output.txt

test-clean:
	sudo rm airodump_output.txt

.PHONY: all clean run test test-setup test-replay test-clean

# 실행 (sudo 권한 필요)
run:
	sudo ./$(TARGET) mon0