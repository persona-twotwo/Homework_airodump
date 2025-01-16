CC = g++
CFLAGS = -Wall -Wextra
LIBS = -lpcap -lpthread

TARGET = airodump
SRCS = airodump.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	make test-clean

test-setup:
	sudo modprobe mac80211_hwsim [radios=2]
	sudo gmon wlan1 mon0

test-setup-clean:
	sudo modprobe mac80211_hwsim -r

test-replay:
	sudo timeout 30 dot11replay -i mon0 airodump.pcap &
	sudo timeout 30 ./${TARGET} mon0

test-replay-file:
	sudo timeout 30 dot11replay -i mon0 airodump.pcap &
	sudo timeout 30 ./${TARGET} mon0 -t &
	sleep 2 &
	sudo timeout 30 tail -f airodump_output.txt

test-clean:
	sudo rm -f airodump_output.txt
	make test-setup-clean

.PHONY: all clean run test test-setup test-replay test-clean

# 실행 (sudo 권한 필요)
run:
	sudo ./$(TARGET) mon0
