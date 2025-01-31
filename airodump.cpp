#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>
#include <functional>

// 0.5초 (usleep 대용)
constexpr int MAX_ESSID_LEN = 32;
constexpr int POLLING_INTERVAL_US = 500000;

// ---------------------------------------------------------------------------
// 뮤텍스 RAII 클래스 (MutexGuard)
// ---------------------------------------------------------------------------
class MutexGuard
{
public:
    explicit MutexGuard(std::mutex &m) : m_(m) { m_.lock(); }
    ~MutexGuard() { m_.unlock(); }
private:
    std::mutex &m_;
};

// ---------------------------------------------------------------------------
// MAC 주소를 다루는 클래스
// ---------------------------------------------------------------------------
class MacAddress
{
public:
    MacAddress()
    {
        memset(mac_, 0, sizeof(mac_));
    }

    // 6바이트 배열로부터 생성
    explicit MacAddress(const uint8_t addr[6])
    {
        memcpy(mac_, addr, 6);
    }

    // 동등 비교
    bool operator==(const MacAddress &other) const {
        return (memcmp(mac_, other.mac_, 6) == 0);
    }

    // 대소 비교(사전순)
    bool operator<(const MacAddress &other) const {
        return (memcmp(mac_, other.mac_, 6) < 0);
    }

    bool operator>(const MacAddress &other) const {
        return (memcmp(mac_, other.mac_, 6) > 0);
    }

    // 문자열로 변환 (ex. "AA:BB:CC:DD:EE:FF")
    std::string toString() const {
        char buf[32];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
        return std::string(buf);
    }

    // 내부 배열 접근 (편의용)
    const uint8_t* data() const { return mac_; }

private:
    uint8_t mac_[6];
};

// ---------------------------------------------------------------------------
// MAC 주소의 해시와 동등 비교 functor( unordered_map 용 )
// ---------------------------------------------------------------------------
struct MacAddressHash {
    std::size_t operator()(const MacAddress &mac) const {
        // 간단히 6바이트를 누적하여 해싱하는 예시 (더 복잡한 방식을 써도 됨)
        const uint8_t* d = mac.data();
        std::size_t h = 0;
        for (int i = 0; i < 6; i++) {
            h = (h << 4) ^ (d[i]);
        }
        return h;
    }
};

struct MacAddressEqual {
    bool operator()(const MacAddress &lhs, const MacAddress &rhs) const {
        return lhs == rhs;
    }
};

// ---------------------------------------------------------------------------
// APInfo 클래스
// ---------------------------------------------------------------------------
class APInfo
{
public:
    APInfo()
    : beaconCount_(0), dataCount_(0), channel_(0), pwr_(0), used_(false)
    {
        memset(encType_, 0, sizeof(encType_));
    }

    APInfo(const MacAddress &mac, const std::string &essid, int pwr, const std::string &encType)
    : bssid_(mac), beaconCount_(essid.empty() ? 0 : 1),
      dataCount_(0), channel_(0), pwr_(pwr), used_(true), essid_(essid)
    {
        strncpy(encType_, encType.c_str(), sizeof(encType_) - 1);
        encType_[sizeof(encType_) - 1] = '\0';
    }

    // 기존 값 갱신
    void update(const std::string &essid, int pwr, const std::string &encType)
    {
        if (!essid.empty()) {
            essid_ = essid;
            beaconCount_++;
        }
        if (pwr != 0) {
            pwr_ = pwr;
        }
        if (!encType.empty()) {
            strncpy(encType_, encType.c_str(), sizeof(encType_) - 1);
            encType_[sizeof(encType_) - 1] = '\0';
        }
        used_ = true;
    }

    bool isUsed() const { return used_; }
    void setUsed(bool used) { used_ = used; }

    const MacAddress& bssid() const { return bssid_; }
    const std::string& essid() const { return essid_; }
    int beaconCount() const { return beaconCount_; }
    int dataCount() const { return dataCount_; }
    int channel() const { return channel_; }
    int pwr() const { return pwr_; }
    const char* encType() const { return encType_; }

private:
    MacAddress bssid_;
    std::string essid_;
    int beaconCount_;
    int dataCount_;
    int channel_;
    int pwr_;
    char encType_[8];
    bool used_;
};

// ---------------------------------------------------------------------------
// 전역 변수
// ---------------------------------------------------------------------------
// unordered_map<MacAddress, APInfo, 해시, 동등비교>
static std::unordered_map<MacAddress, APInfo, MacAddressHash, MacAddressEqual> g_apMap;
static std::mutex g_apMapMutex;

static char g_iface[64] = {0};
static std::atomic<bool> g_channelHop(true);
static std::atomic<int>  g_currentChannel(1);
static std::atomic<int>  g_timeOut(0);

static pcap_t *g_handle = nullptr;
static bool g_testMode = false;
static FILE* g_outputFile = nullptr;

// ---------------------------------------------------------------------------
// APInfo 관리 함수
// ---------------------------------------------------------------------------
static void updateAPInfo(const uint8_t bssid[6], 
                         const std::string &essid, 
                         int pwr, 
                         const std::string &encType)
{
    MacAddress mac(bssid);
    MutexGuard guard(g_apMapMutex);

    auto it = g_apMap.find(mac);
    if (it == g_apMap.end()) {
        // 새 AP 추가
        APInfo ap(mac, essid, pwr, encType);
        g_apMap.emplace(mac, ap);
    } else {
        // 기존 AP 갱신
        it->second.update(essid, pwr, encType);
    }
}

// ---------------------------------------------------------------------------
// 패킷을 담고 파싱하는 클래스
// ---------------------------------------------------------------------------

/*
 * 간단히 Radiotap 헤더에서 dBm_Antenna_Signal (bit5)을 추출하는 예제입니다.
 * 실제 Radiotap 헤더는 여러 개의 32비트 present word와 확장 비트를 
 * 가질 수 있지만, 여기서는 간소화된 형태로만 처리합니다.
 */
class Packet
{
public:
    Packet(const uint8_t *data, uint32_t length)
    : data_(data), length_(length), valid_(false),
      rssi_(-30) // 기본값 -30
    {
        parseRadiotap();
    }

    bool isValid() const { return valid_; }
    bool isBeaconFrame() const
    {
        // type == 0 (Management), subtype == 8 (Beacon)
        return (type_ == 0 && subtype_ == 8);
    }

    const uint8_t* bssid() const { return bssid_; }
    std::string ssid() const { return ssid_; }
    std::string encryption() const { return encryption_; }
    int rssi() const { return rssi_; }

private:
    void parseRadiotap()
    {
        // 최소한의 radiotap 헤더 길이 확인
        if (length_ < 8) {
            return;
        }

        uint16_t radiotapLen = data_[2] | (data_[3] << 8);
        if (radiotapLen > length_) {
            return;
        }

        // present 필드 (첫 번째 32비트만 파싱하는 간소화 버전)
        if (radiotapLen >= 12) {
            uint32_t present = data_[8] 
                             | (data_[9] << 8) 
                             | (data_[10] << 16) 
                             | (data_[11] << 24);

            // radiotap header 시작 이후, 필드를 스캔하기 위한 offset
            // (version=1byte, pad=1byte, length=2byte, present=4byte = 총 8바이트 + present=4=12바이트)
            size_t rtOffset = 12;  

            // bit0: TSFT (8바이트)
            if (present & (1 << 0)) {
                rtOffset += 8;
            }
            // bit1: Flags (1바이트)
            if (present & (1 << 1)) {
                rtOffset += 1;
            }
            // bit2: Rate (1바이트)
            if (present & (1 << 2)) {
                rtOffset += 1;
            }
            // bit3: Channel (4바이트)
            if (present & (1 << 3)) {
                rtOffset += 4;
            }
            // bit4: FHSS (2바이트)
            if (present & (1 << 4)) {
                rtOffset += 2;
            }
            // bit5: dBm_Antenna_Signal (1바이트)
            if (present & (1 << 5)) {
                // 범위 확인
                if (rtOffset + 1 <= radiotapLen) {
                    rssi_ = static_cast<int8_t>(data_[rtOffset]);
                }
                rtOffset += 1;
            } else {
                // 없으면 기본값 -30 유지
            }
            // (이후 bit6: dBm_Antenna_Noise, bit7: Lock Quality 등등은 생략)
        }

        // radiotapLen 뒤가 802.11 헤더 시작
        const uint8_t *ieee80211Hdr = data_ + radiotapLen;
        uint32_t ieee80211HdrLen = length_ - radiotapLen;
        if (ieee80211HdrLen < 24) {
            return;
        }

        uint16_t fc = ieee80211Hdr[0] | (ieee80211Hdr[1] << 8);
        type_    = (fc & 0x0C) >> 2;   // bits 2-3
        subtype_ = (fc & 0xF0) >> 4;   // bits 4-7

        // BSSID는 16바이트 오프셋에서 6바이트
        memcpy(bssid_, ieee80211Hdr + 16, 6);

        // Beacon이면 SSID, 암호화 파싱
        if (isBeaconFrame()) {
            parseBeacon(ieee80211Hdr, ieee80211HdrLen);
        }

        valid_ = true;
    }

    void parseBeacon(const uint8_t *hdr, uint32_t hdrLen)
    {
        // Beacon Body = 802.11 헤더(24) + Fixed Params(12) 이후
        const uint8_t *body = hdr + 24;
        int bodyLen = hdrLen - 24;
        if (bodyLen < 12) {
            return;
        }
        const uint8_t *iePtr = body + 12;
        int ieLen = bodyLen - 12;

        ssid_.clear();
        encryption_ = "OPN"; // 기본값

        int idx = 0;
        while (idx + 2 < ieLen) {
            uint8_t tagNum = iePtr[idx];
            uint8_t tagLen = iePtr[idx + 1];
            const uint8_t *tagData = &iePtr[idx + 2];

            if (idx + 2 + tagLen > ieLen) {
                break;
            }

            // SSID
            if (tagNum == 0) {
                int copyLen = (tagLen > MAX_ESSID_LEN) ? MAX_ESSID_LEN : tagLen;
                ssid_.assign(reinterpret_cast<const char*>(tagData), copyLen);
            }
            // RSN / WPA2
            if (tagNum == 48) {
                encryption_ = "WPA2";
            }

            idx += (2 + tagLen);
        }
    }

private:
    const uint8_t *data_;
    uint32_t length_;
    bool valid_;

    int rssi_;
    uint8_t bssid_[6];
    uint8_t type_;
    uint8_t subtype_;

    std::string ssid_;
    std::string encryption_;
};

// ---------------------------------------------------------------------------
// 패킷 콜백
// ---------------------------------------------------------------------------
static void packetHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    (void)user;

    Packet pkt(bytes, h->caplen);
    if (!pkt.isValid()) {
        return;
    }

    if (pkt.isBeaconFrame()) {
        updateAPInfo(pkt.bssid(), pkt.ssid(), pkt.rssi(), pkt.encryption());
    }
}

// ---------------------------------------------------------------------------
// 화면/파일 출력 쓰레드
// ---------------------------------------------------------------------------
void printThreadFunc()
{
    while (true) {
        {
            MutexGuard guard(g_apMapMutex);
            // 화면 또는 파일에 찍을 내용을 임시 문자열에 담기
            std::string output;
            output += "CH " + std::to_string(g_currentChannel.load()) + "\n";
            output += " BSSID              PWR   Beacons   ENC   ESSID\n";
            output += "-----------------------------------------------------------------\n";

            for (auto &kv : g_apMap) {
                const MacAddress &mac = kv.first;
                const APInfo &ap = kv.second;
                if (!ap.isUsed()) continue;

                // BSSID 문자열
                std::string bssidStr = mac.toString();

                char lineBuf[256];
                snprintf(lineBuf, sizeof(lineBuf),
                         " %-17s  %4d  %7d   %-5s  %s\n",
                         bssidStr.c_str(),
                         ap.pwr(),
                         ap.beaconCount(),
                         ap.encType(),
                         ap.essid().c_str());
                output += lineBuf;
            }

            // 실제 출력
            if (!g_testMode) {
                // 화면 지우기 (리눅스 기준)
                system("clear");
                std::cout << output << std::flush;
            } else {
                if (g_outputFile) {
                    fprintf(g_outputFile, "%s\n", output.c_str());
                    fflush(g_outputFile);
                }
            }
        }

        // 타임아웃 체크
        if (g_timeOut > 0) {
            g_timeOut -= POLLING_INTERVAL_US;
            if (g_timeOut <= 0) {
                g_channelHop = false;
                if (g_handle) {
                    pcap_breakloop(g_handle);
                }
                return;
            }
        }

        std::this_thread::sleep_for(std::chrono::microseconds(POLLING_INTERVAL_US));
    }
}

// ---------------------------------------------------------------------------
// 채널 호핑 쓰레드
// ---------------------------------------------------------------------------
void channelHopThreadFunc()
{
    // 2.4GHz 예: 1, 6, 11
    int channels[] = {1, 6, 11};
    size_t numChannels = sizeof(channels) / sizeof(channels[0]);
    size_t idx = 0;

    while (g_channelHop) {
        int ch = channels[idx];
        g_currentChannel = ch;

        // "iwconfig <iface> channel <ch>"
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "iwconfig %s channel %d", g_iface, ch);
        system(cmd);

        idx = (idx + 1) % numChannels;
        std::this_thread::sleep_for(std::chrono::microseconds(POLLING_INTERVAL_US));
    }
}

// ---------------------------------------------------------------------------
// main 함수
// ---------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "syntax : airodump <interface> [-t|-s <seconds>|-ch <channel>]\n"
                  << "sample : airodump mon0\n"
                  << "options:\n"
                  << "  -t : test mode (save output to file)\n"
                  << "  -s <seconds> : stop after specified seconds\n"
                  << "  -ch <channel> : fix channel (no hopping)\n";
        return -1;
    }

    strncpy(g_iface, argv[1], sizeof(g_iface) - 1);
    g_iface[sizeof(g_iface) - 1] = '\0';

    // 옵션 파싱
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-t") == 0) {
            g_testMode = true;
            g_outputFile = fopen("airodump_output.txt", "w");
            if (!g_outputFile) {
                std::cerr << "Failed to open output file\n";
                return -1;
            }
        } else if (strcmp(argv[i], "-s") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: -s option requires seconds parameter\n";
                return -1;
            }
            g_timeOut = std::atoi(argv[++i]) * 1000000;
        } else if (strcmp(argv[i], "-ch") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: -ch option requires channel parameter\n";
                return -1;
            }
            g_channelHop = false;
            g_currentChannel = std::atoi(argv[++i]);
        }
    }

    // pcap 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(g_iface, BUFSIZ, 1, 1000, errbuf);
    if (!g_handle) {
        std::cerr << "pcap_open_live(" << g_iface << ") return null - " << errbuf << "\n";
        return -1;
    }

    // 쓰레드: 출력
    std::thread printThread(printThreadFunc);

    // 채널 호핑
    std::thread hopThread;
    if (g_channelHop) {
        hopThread = std::thread(channelHopThreadFunc);
    }

    std::cout << "[*] Start capturing on " << g_iface << " ...\n";

    // 패킷 캡처 루프 시작
    pcap_loop(g_handle, 0, packetHandler, nullptr);

    // 종료 처리
    g_channelHop = false;
    if (hopThread.joinable()) {
        hopThread.join();
    }

    if (g_handle) {
        pcap_close(g_handle);
        g_handle = nullptr;
    }

    if (printThread.joinable()) {
        printThread.join();
    }

    if (g_outputFile) {
        fclose(g_outputFile);
        g_outputFile = nullptr;
    }

    return 0;
}
