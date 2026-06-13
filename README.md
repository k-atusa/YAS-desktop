# YAS-desktop v1.4.0

project USAG: Yet Another Security desktop version

> YAS is powerful security tool with archiving, transmitting, signing, and encrypting functions.

## CLI Usage

| Option | Input | Info | 정보 |
| :--- | :--- | :--- | :--- |
| -m | pack, unpack, send, recv, genkey, sign, enc, dec | Sets the working mode. | 작업 모드를 설정합니다. |
| -o | path | Sets the output path. | 출력 경로를 설정합니다. |
| -t | text, ip:port/secret | Inputs text, IP address, port, or shared secret. | 텍스트나 IP, 포트, 공유 비밀값을 입력합니다. |
| -nopad | | Disable opsec padding | 패딩을 비활성화합니다. |
| -msg | text | Sets the non-secured plaintext message. | 평문 메세지를 설정합니다. |
| -smsg | text | Sets the secured message. | 보안 메세지를 설정합니다. |
| -pw | text | Sets the password. | 비밀번호를 설정합니다. |
| -kf | filepath | Sets the key file path. | 키 파일 경로를 설정합니다. |
| -pub | text, filepath | Sets the peer public key. | 상대방의 공개키를 설정합니다. |
| -mypub | text, filepath | Sets the my public key. | 나의 공개키를 설정합니다. |
| -mypri | text, filepath | Sets the my private key. | 나의 개인키를 설정합니다. |
| | | Arguments following the options are interpreted as target paths. | 옵션 이후 인자는 타겟 경로로 해석됩니다. |

Algorithm flags

| Category | Keywords | Info |
| :--- | :--- | :--- |
| Image | webp, png, bin | Sets camouflage image format (Default: webp). |
| Packing | zip1, tar1 | Sets archiving format (Default: tar1). |
| Enc Mode | gcm1, gcmx1 | Sets body encryption algorithm (Default: gcmx1). |
| PW Mode | sha3, pbk2, arg2 | Sets password derivation algorithm (Default: arg2). |
| Pub Mode | rsa1, rsa2, ecc1, pqc1 | Sets asymmetric key type (Default: pqc1). |

- pack/unpack: 여러 파일을 하나로 아카이빙하거나 패키징된 파일을 해제합니다. Archives multiple files into one or extracts a packaged file.
- send/recv: USAG-TP1 프로토콜로 메시지나 파일들을 다른 기기에 안전하게 전송합니다. Securely transfers messages or files to another device using the USAG-TP1 protocol.
- genkey: 공개키와 개인키 쌍을 생성합니다. Generates a public and private key pair.
- sign: 개인키로 파일에 서명하거나 공개키로 서명을 검증합니다. Signs a file with a private key or verifies a signature with a public key.
- enc/dec: 메시지나 파일들을 암호화하거나 복호화합니다. Encrypts or decrypts messages or files.

## GUI Usage

| function | Info | 정보 |
| :--- | :--- | :--- |
| Pack/Unpack | Handles archive packing and unpacking. | 아카이브 패킹과 언패킹 기능입니다. |
| Sign/Verify | Generates and verifies digital signatures. | 전자서명 생성/검증 기능입니다. |
| Send | Transfers files to devices on the local network via the TP1 protocol. | TP1 프로토콜로 근거리 네트워크 상의 기기로 파일을 전송합니다. |
| Receive | Receives files using the TP1 protocol. | TP1 프로토콜로 파일을 수신합니다. |
| Encrypt pw | Encrypts files or messages based on a password. | 비밀번호 기반으로 파일이나 메세지를 암호화합니다. |
| Decrypt pw | Decrypts files or messages based on a password. | 비밀번호 기반으로 파일이나 메세지를 복호화합니다. |
| Encrypt pub | Encrypts files or messages using a public key. | 공개키 기반으로 파일이나 메세지를 암호화합니다. |
| Decrypt pub | Decrypts files or messages using a public key. | 공개키 기반으로 파일이나 메세지를 복호화합니다. |
| Contacts | Manages IP shortcuts, public key address books, and account key files. | IP 바로가기, 공개키 주소록, 계정 키 파일을 관리합니다. |
| Account | Manages account key pairs or allows for password resets. | 계정의 키 쌍을 관리하거나 비빌번호를 재설정 할 수 있습니다. |
| Extend | Extends the login session. | 로그인 세션을 연장합니다. |
| Logout | Terminates the login session. | 로그인 세션을 종료합니다. |

- config.json은 암호화되지 않으며 자동 세션 만료와 계정 파일 경로 등을 보관합니다. config.json is not encrypted and stores session expiration settings and account file paths.
- 계정 파일은 Opsec 형식으로 암호화되며 내부에 공개키/개인키 쌍과 키 파일을 보관할 수 있습니다. Account files are encrypted in Opsec format and can store public/private key pairs and key files.
- 공개키는 변조되지 않는 채널로 공유한다면 노출되어도 괜찮지만, 개인키는 절대 유출되어선 안 됩니다. While public keys can be shared (provided the channel is secure), private keys must never be exposed.
- 키 파일이나 개인키, 상대 공개키 등을 AFT 볼트 안에 보관하고 TP1으로 받아오면 더 안전합니다. It is safer to store key files, private keys, and relative public keys in an AFT Vault and retrieve them via TP1.

#### config

| Option | Type | Info | 정보 |
| :--- | :--- | :--- | :--- |
| expire | int | Auto expire time in minutes. (Set 0 to disable auto expire) | 자동 세션 만료 시간. (0으로 설정 시 비활성화) |
| size | float | Fyne UI Scaling factor | Fyne UI 배율 |
| dopad | bool | Enables Opsec padding | Opsec 패딩 활성화 여부 |
| initdir | string | Initial directory (no change if empty) | 초기 디렉토리 (비어있으면 변경하지 않음) |
| accounts | string[] | Account file paths | 계정 파일 경로 목록 |
| ips | string[] | IP/port shortcuts | IP/포트 단축 목록 |

## Build Executable

This application uses Go programming language. [Install Go](https://go.dev/) to build yourself, or download pre-built release binary. It takes few minutes to download and build GUI version.

windows cli
```bat
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o yas-lite.exe core.go lite.go
```

linux/mac cli
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o yas-lite core.go lite.go
```

windows gui
```bat
go mod init example.com
go mod tidy
go build -ldflags="-H windowsgui -s -w" -trimpath -o yas.exe core.go pages.go main.go
```

linux/mac gui
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o yas core.go pages.go main.go
```

fyne2 GUI requires C compiler and X11 environment. Selection dialog requires Zenity. check and install following packages before build.
```bash
gcc --version
sudo apt install zenity
sudo apt-get install pkg-config libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libxxf86vm-dev
```
