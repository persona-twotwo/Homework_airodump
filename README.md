# Airodump

무선 네트워크 모니터링 도구입니다. 주변의 Wi-Fi AP(Access Point)들을 스캔하고 정보를 수집합니다.

## 기능

- 실시간 AP 스캔 및 모니터링
- 채널 호핑을 통한 다중 채널 스캔
- AP 정보 표시:
  - BSSID (AP의 MAC 주소)
  - 신호 강도 (PWR)
  - Beacon 프레임 수
  - 데이터 프레임 수
  - 암호화 방식 (WPA2, WPA, WEP, OPN)
  - ESSID (AP 이름)

## 빌드
```
make
```

## 기본 실행
```
sudo ./airodump <interface>
```

예시
```
sudo ./airodump mon0
```

## 테스트 모드
- 테스트 모드는 출력 파일을 생성하고, 테스트 파일을 재생하여 테스트를 진행합니다.
```
make test-setup
# 테스트를 위한 가상 무선 인터페이스 생성
```
```
make test-setup-clean
# 무선 인터페이스 삭제
```
```
make test-replay
# 파일 재생을 통한 테스트
```
```
make test-replay-file
# 파일 재생을 통한 테스트 (파일로 출력)
```
```
make test-clean
# 테스트 환경 정리
```