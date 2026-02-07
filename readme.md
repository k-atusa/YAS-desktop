# YAS-desktop v0.1

project USAG: Yet Another Security desktop version

> YAS is powerful security tool with archiving, transmitting, signing, and encrypting functions.

## CLI Usage

| Option | Input | Info | 정보 |
| :--- | :--- | :--- | :--- |
| -m | zip, unzip, send, recv, genkey, sign, enc, dec, version | Sets the working mode. | 작업 모드를 설정합니다. |
| -o | path | Sets the output path. | 출력 경로를 설정합니다. |
| -t | text, ip:port | Inputs text, IP address, or port. | 텍스트나 IP, 포트를 입력합니다. |
| -msg | text | Sets the non-secured plaintext message. | 평문 메세지를 설정합니다. |
| -smsg | text | Sets the secured message. | 보안 메세지를 설정합니다. |
| -pw | text | Sets the password. | 비밀번호를 설정합니다. |
| -kf | filepath | Sets the key file path. | 키 파일 경로를 설정합니다. |
| -pub | text, filepath | Sets the public key. | 공개키를 설정합니다. |
| -pri | text, filepath | Sets the private key. | 개인키를 설정합니다. |
| -zip | | Uses ZIP format for archiving. | 아카이빙 시 zip 형식을 사용합니다. |
| -legacy | | Enables Legacy Mode (RSA, PBKDF2). | 레거시 모드(RSA, PBKDF2)를 킵니다. |
| -bits | 2048, 3072, 4096 | Sets the key size when generating RSA keys. | RSA 키 생성 시 크기를 설정합니다. |
| -pre | none, zippng, zipwebp, aespng, aeswebp, cloudpng, cloudwebp | Sets the camouflage header for file encryption. | 파일 암호화 위장헤더를 설정합니다. |
| -tmp | dirpath | Sets the temporary directory path. | 임시폴더 경로를 설정합니다. |
| | | Arguments following the options are interpreted as target paths. | 옵션 이후 인자는 타겟 경로로 해석됩니다. |

- zip/unzip: 여러 파일을 하나로 아카이빙하거나 패키징된 파일을 해제합니다. Archives multiple files into one or extracts a packaged file.
- send/recv: USAG-TP1 프로토콜로 메시지나 파일들을 다른 기기에 안전하게 전송합니다. Securely transfers messages or files to another device using the USAG-TP1 protocol.
- genkey: 공개키와 개인키 쌍을 생성합니다. Generates a public and private key pair.
- sign: 개인키로 파일에 서명하거나 공개키로 서명을 검증합니다. Signs a file with a private key or verifies a signature with a public key.
- enc/dec: 메시지나 파일들을 암호화하거나 복호화합니다. Encrypts or decrypts messages or files.

## GUI Usage

## Build Executable

This application uses Go programming language. [Install Go](https://go.dev/) to build yourself, or download pre-built release binary. It takes few minutes to download and build GUI version.

windows cli
```bat
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o yascli.exe lib.go lite.go
```

linux/mac cli
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o yascli lib.go lite.go
```

windows gui
```bat
go mod init example.com
go mod tidy
go build -ldflags="-H windowsgui -s -w" -trimpath -o yasgui.exe lib.go main.go
```

linux/mac gui
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o yasgui lib.go main.go
```

fyne2 GUI requires C compiler and X11 environment. check and install following packages before build.
```bash
gcc --version
sudo apt-get install pkg-config libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libxxf86vm-dev
```

## USAG-TP1 protocol

`USAG-TP1`은 근거리 네트워크에서 데이터나 zip 파일을 종단간 암호화로 전송하는 프로토콜입니다. ECC1 암호화가 기본이지만 송신자 설정에 따라 RSA1 암호화도 지원합니다. 기본 포트는 데이터 전송은 8001, 파일 전송은 8002입니다.
`USAG-TP1` is a protocol for end-to-end encrypted transfer of data or ZIP files over a local area network. While ECC1 encryption is the default, it also supports RSA1 encryption based on the sender's configuration. The default port for data transfer is 8001, and for file transfer is 8002.

- 수신자가 포트를 엽니다. The receiver opens a port.
- 송신자가 포트를 열고 TCP 소켓을 연결합니다. The sender opens a port and establishes a TCP socket connection.
- 송신자가 공개키를 만들고 핸드쉐이크 패킷(매직 4B, 모드 2B, 공개키길이 2B, 공개키)을 전송합니다. The sender generates a public key and transmits a handshake packet (Magic 4B, Mode 2B, Public Key Length 2B, Public Key).
- 수신자가 공개키를 만들고 통신개시 패킷(공개키길이 2B, 공개키)을 전송합니다. The receiver generates its own public key and transmits a communication initialization packet (Public Key Length 2B, Public Key).
- 송신자가 수신자의 공개키로 내용을 암호화하고 서명합니다. 동시에 하트비트 패킷(8B, 0은 진행 중, 최댓값은 오류 발생)을 보냅니다. The sender encrypts and signs the content using the receiver's public key. Simultaneously, it sends heartbeat packets (8B; 0 indicates "in progress," while the maximum value indicates an "error").
- 암호화가 완료되면 전송예고 패킷(8B, 총 전송 크기)을 보냅니다. Once encryption is complete, the sender transmits a transmission announcement packet (8B; total transmission size).
- 송신자는 데이터를 전송하고 수신자가 완료 패킷(8B)을 반송하여 통신을 끝냅니다. The sender transfers the data, and the receiver ends the communication by returning a completion packet (8B).