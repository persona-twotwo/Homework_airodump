#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h> 



#define MAX_AP 256
#define MAX_ESSID_LEN 32
#define POLLING_INTERVAL 500000

typedef struct _ap_info {
    unsigned char bssid[6];
    char essid[MAX_ESSID_LEN+1];
    int beacon_count;
    int data_count;
    int channel;
    int pwr;            // RSSI값 (Radiotap Header에서 추출)
    char enc_type[8];   // "WPA2", "WPA", "WEP", "OPN" 등
    int used;           // 해당 구조체 사용 여부
} ap_info_t;

// 전역 AP 정보 테이블
static ap_info_t g_ap_list[MAX_AP];
static pthread_mutex_t g_ap_list_lock = PTHREAD_MUTEX_INITIALIZER;

// 모니터링 중인 인터페이스 이름
static char g_iface[64] = {0};

// 채널 호핑을 할지 여부
static int g_channel_hop = 1;
static int g_current_channel = 1;  // 현재 채널 정보를 저장할 변수

// 전역 변수 섹션에 추가
static FILE* g_output_file = NULL;  // 출력 파일 포인터
static int g_test_mode = 0;         // 테스트 모드 플래그
int g_time_out = 0;
static pcap_t *g_handle = NULL;  // pcap 핸들을 전역 변수로 선언


// ----------------------------------------------------------------------------
// 헬퍼 함수
// ----------------------------------------------------------------------------

static void print_mac(const unsigned char *mac, char *buf, size_t buf_size) {
    snprintf(buf, buf_size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// AP 리스트에서 BSSID를 검색하여 있으면 해당 인덱스, 없으면 -1
static int find_ap_index(const unsigned char *bssid) {
    for (int i = 0; i < MAX_AP; i++) {
        if (!g_ap_list[i].used) continue;
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

// AP 리스트에 새로운 항목을 추가하거나, 기존 항목을 갱신
static int update_ap_info(const unsigned char *bssid, const char *essid, 
                          int pwr, const char *enc_type) {
    int idx = find_ap_index(bssid);
    pthread_mutex_lock(&g_ap_list_lock);
    if (idx < 0) {
        // 새로운 AP
        for (int i = 0; i < MAX_AP; i++) {
            if (!g_ap_list[i].used) {
                memcpy(g_ap_list[i].bssid, bssid, 6);
                if (essid) {
                    strncpy(g_ap_list[i].essid, essid, MAX_ESSID_LEN);
                    g_ap_list[i].essid[MAX_ESSID_LEN] = '\0';
                }
                if (enc_type) {
                    strncpy(g_ap_list[i].enc_type, enc_type, sizeof(g_ap_list[i].enc_type)-1);
                    g_ap_list[i].enc_type[sizeof(g_ap_list[i].enc_type)-1] = '\0';
                }
                g_ap_list[i].pwr = pwr;
                g_ap_list[i].beacon_count = (essid != NULL) ? 1 : 0;
                g_ap_list[i].data_count = 0;
                g_ap_list[i].used = 1;
                pthread_mutex_unlock(&g_ap_list_lock);
                return 0;
            }
        }
    } else {
        // 기존 AP 갱신
        if (essid && strlen(essid) > 0) {
            strncpy(g_ap_list[idx].essid, essid, MAX_ESSID_LEN);
            g_ap_list[idx].essid[MAX_ESSID_LEN] = '\0';
            g_ap_list[idx].beacon_count++;
        }
        if (pwr != 0) {
            g_ap_list[idx].pwr = pwr;
        }
        if (enc_type && strlen(enc_type) > 0) {
            strncpy(g_ap_list[idx].enc_type, enc_type, sizeof(g_ap_list[idx].enc_type)-1);
            g_ap_list[idx].enc_type[sizeof(g_ap_list[idx].enc_type)-1] = '\0';
        }
    }
    pthread_mutex_unlock(&g_ap_list_lock);
    return 0;
}

// ----------------------------------------------------------------------------
// 패킷 파싱 함수 (주요 로직)
// ----------------------------------------------------------------------------

// Radiotap Header 길이를 구한 뒤, 802.11 헤더를 파싱
static void parse_packet(const unsigned char *packet, struct pcap_pkthdr header) {
    // 1) Radiotap Header에서 길이 추출
    if (header.caplen < 8) {
        return; // radiotap header가 최소 크기도 안 될 경우
    }
    
    uint16_t radiotap_len = packet[2] | (packet[3] << 8);
    if (radiotap_len > header.caplen) {
        return; // 잘못된 radiotap 길이
    }

    // (예시) RSSI(PWR) 추출 로직(간단화된 예시)
    // 실제로는 radiotap header bitmap을 파악해서 신호 강도 필드를 찾아야 함
    int rssi = 0; 
    // radiotap_len 이후에 존재하는 필드들 중에 신호 강도를 찾는 과정 필요
    // 여기서는 예시로 rssi를 고정값으로 처리하거나,
    // 실제 구현 시 radiotap 헤더를 모두 파싱해야 함
    rssi = -30;  // 예시로 고정

    // 2) 802.11 헤더 시작 위치
    const unsigned char *ieee80211_hdr = packet + radiotap_len;
    int ieee80211_hdr_len = header.caplen - radiotap_len;
    if (ieee80211_hdr_len < 24) {
        return; // 최소한의 802.11 MAC 헤더보다 작으면 return
    }

    // Frame Control 필드
    uint16_t fc = ieee80211_hdr[0] | (ieee80211_hdr[1] << 8);
    uint8_t type = (fc & 0x0C) >> 2;   // type = bits 2-3
    uint8_t subtype = (fc & 0xF0) >> 4; // subtype = bits 4-7

    // 3) Beacon Frame 체크 (type = 0(Management), subtype = 8(Beacon))
    if (type == 0 && subtype == 8) {
        const unsigned char *bssid_ptr = ieee80211_hdr + 16;
        
        
        const unsigned char *body = ieee80211_hdr + 24; 
        int body_len = ieee80211_hdr_len - 24;
        if (body_len < 12) {
            return; 
        }
        
        // Fixed parameter 12바이트 스킵 후 IE(Information Elements)부터 파싱
        const unsigned char *ie_ptr = body + 12;
        int ie_len = body_len - 12;
        char ssid_buf[MAX_ESSID_LEN+1] = {0};
        char enc_buf[8] = "OPN"; // 기본값(오픈)

        // SSID IE는 ID 0
        // 실제로는 한 프레임에 여러 IE가 있을 수 있으니 while 루프로 순회해야 함
        // 여기서는 예시를 위해 간단히 파싱
        int idx = 0;
        while (idx + 2 < ie_len) {
            uint8_t tag_num = ie_ptr[idx];
            uint8_t tag_len = ie_ptr[idx + 1];
            const unsigned char *tag_data = &ie_ptr[idx + 2];
            if (idx + 2 + tag_len > ie_len) {
                break; // 범위 초과
            }

            // SSID
            if (tag_num == 0) {
                // ESSID
                int copy_len = (tag_len > MAX_ESSID_LEN) ? MAX_ESSID_LEN : tag_len;
                memcpy(ssid_buf, tag_data, copy_len);
                ssid_buf[copy_len] = '\0';
            }
            // RSN/WPA/WEP 등의 Encryption 체크는
            // tag_num == 48(RSN), vendor specific 등으로 파악해야 함.
            // 간단히 여기서는 WPA2라고 가정
            if (tag_num == 48) {
                strncpy(enc_buf, "WPA2", sizeof(enc_buf));
            }
            
            idx += 2 + tag_len;
        }

        // AP 정보 업데이트
        update_ap_info(bssid_ptr, ssid_buf, rssi, enc_buf);
    }
    else if (type == 2) {
        // Data frame일 경우 #Data 카운트 등 업데이트 가능
        // BSSID 위치, To DS/From DS 비트, QoS 헤더 등에 따라 달라짐
        // 예시에서는 단순히 SA / BSSID로 처리
        // ...
    }
}

// ----------------------------------------------------------------------------
// 패킷 콜백 함수
// ----------------------------------------------------------------------------

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    parse_packet(bytes, *h);
}

// ----------------------------------------------------------------------------
// 출력 쓰레드(일정 주기로 화면에 정보를 표시)
// ----------------------------------------------------------------------------

void *print_thread_func(void *arg) {
    (void)arg;
    char output_buffer[4096];  // 출력을 저장할 버퍼
    
    while (1) {
        // 출력을 버퍼에 작성
        int offset = 0;
        offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset, 
                         "CH %d\n", g_current_channel);
        offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset,
                         " BSSID              PWR   Beacons  #Data   ENC   ESSID\n");
        offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset,
                         "-----------------------------------------------------------------\n");

        pthread_mutex_lock(&g_ap_list_lock);
        for (int i = 0; i < MAX_AP; i++) {
            if (!g_ap_list[i].used) continue;

            char bssid_str[32];
            print_mac(g_ap_list[i].bssid, bssid_str, sizeof(bssid_str));

            offset += snprintf(output_buffer + offset, sizeof(output_buffer) - offset,
                             " %-17s  %4d  %7d  %5d   %-5s  %s\n",
                             bssid_str,
                             g_ap_list[i].pwr,
                             g_ap_list[i].beacon_count,
                             g_ap_list[i].data_count,
                             g_ap_list[i].enc_type,
                             g_ap_list[i].essid);
        }
        pthread_mutex_unlock(&g_ap_list_lock);

        // 화면에 출력
        if (!g_test_mode) {
            system("clear");
            printf("%s", output_buffer);
            fflush(stdout);
        }

        // 파일에 출력 (테스트 모드일 때)
        if (g_test_mode && g_output_file) {
            fprintf(g_output_file, "%s\n", output_buffer);
            fflush(g_output_file);
        }

        usleep(POLLING_INTERVAL); // 0.5초 간격으로 갱신
        if (g_time_out > 0) {
            g_time_out -= POLLING_INTERVAL;
            if (g_time_out <= 0) {
                g_channel_hop = 0;
                if (g_handle) {
                    pcap_breakloop(g_handle);  // 메인 캡처 루프 종료
                }
                return NULL;
            }
        }
    }
    return NULL;
}

// ----------------------------------------------------------------------------
// 채널 호핑 쓰레드(가능하다면)
// ----------------------------------------------------------------------------

void *channel_hop_thread_func(void *arg) {
    (void)arg;
    int channels[] = {1, 6, 11}; // 2.4GHz 대역 예시
    int num_channels = sizeof(channels)/sizeof(channels[0]);
    int idx = 0;

    while (g_channel_hop) {
        char cmd[128];
        g_current_channel = channels[idx];  // 현재 채널 업데이트
        snprintf(cmd, sizeof(cmd), "iwconfig %s channel %d", g_iface, channels[idx]);
        system(cmd);
        idx = (idx + 1) % num_channels;
        usleep(POLLING_INTERVAL); // 0.5초 간격으로 갱신
    }
    return NULL;
}

// ----------------------------------------------------------------------------
// main 함수
// ----------------------------------------------------------------------------

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "syntax : airodump <interface> [-t|-s <seconds>]\n");
        fprintf(stderr, "sample : airodump mon0\n");
        fprintf(stderr, "options:\n");
        fprintf(stderr, "  -t : test mode (save output to file)\n");
        fprintf(stderr, "  -s <seconds> : stop after specified seconds\n");
        return -1;
    }

    // 옵션 파싱
    strncpy(g_iface, argv[1], sizeof(g_iface)-1);
    g_iface[sizeof(g_iface)-1] = '\0';

    // 테스트 모드 체크
    if (argc > 2 && strcmp(argv[2], "-t") == 0) {
        g_test_mode = 1;
        g_output_file = fopen("airodump_output.txt", "w");
        if (!g_output_file) {
            fprintf(stderr, "Failed to open output file\n");
            return -1;
        }
    }

    // time out 체크 (-s 옵션)
    if (argc > 2 && strcmp(argv[2], "-s") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: -s option requires seconds parameter\n");
            return -1;
        }
        g_time_out = atoi(argv[3]) * 1000000;
    }

    //channel hop 체크
    if (argc > 2 && strcmp(argv[2], "-ch") == 0) {
        g_channel_hop = 0;
        g_current_channel = atoi(argv[3]);
    }

    

    // libpcap 관련 변수
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1) 인터페이스 열기
    g_handle = pcap_open_live(g_iface, BUFSIZ, 1, 1000, errbuf);
    if (g_handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", g_iface, errbuf);
        return -1;
    }

    // 2) 802.11 무선 헤더(링크 타입)가 맞는지 확인
    int datalink = pcap_datalink(g_handle);
    if (datalink != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "[-] %s is not in Radiotap(IEEE802_11_RADIO) mode.\n", g_iface);
        pcap_close(g_handle);
        g_handle = NULL;
        return -1;
    }

    // 3) 출력 쓰레드 시작
    pthread_t print_thread;
    if (pthread_create(&print_thread, NULL, print_thread_func, NULL) != 0) {
        fprintf(stderr, "pthread_create print_thread failed\n");
        pcap_close(g_handle);
        g_handle = NULL;
        return -1;
    }

    // 4) 채널 호핑 쓰레드 시작(선택)
    pthread_t hop_thread;
    if (g_channel_hop) {
        if (pthread_create(&hop_thread, NULL, channel_hop_thread_func, NULL) != 0) {
            fprintf(stderr, "pthread_create hop_thread failed\n");
            pcap_close(g_handle);
            g_handle = NULL;
            return -1;
        }
    }

    // 5) 패킷 캡처 루프 시작
    printf("[*] Start capturing on %s ...\n", g_iface);
    pcap_loop(g_handle, 0, packet_handler, NULL);

    // 6) 리소스 정리
    g_channel_hop = 0; // 채널 호핑 쓰레드 종료 유도
    pcap_close(g_handle);
    g_handle = NULL;

    if (g_output_file) {
        fclose(g_output_file);
    }

    return 0;
}
