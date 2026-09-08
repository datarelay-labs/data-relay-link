# FRP Auto Deploy — Product Master Document

> **Document role:** Product Charter + Product Specification + Architecture Principles + Roadmap  
> **Repository:** `datarelay-labs/frp-auto-deploy`  
> **Canonical repository path:** `docs/PRODUCT_MASTER.md`  
> **Document status:** Master / Living Document  
> **Last updated:** 2026-09-08  
> **Current stable:** Project `2.2.1` / tag `v2.2.1` / FRP `0.71.0`  
> **Release commit:** `19d4b6fb8a9bee2d477ace6f5c3ed70310e7ea8f`  
> **Qualified candidate:** `2140be5b6342c3651c16a458f8ea1bc9b577d992` — tree-identical to release commit  
> **Release qualification:** Double Full Real E2E `PASS / PASS` on the same exact candidate HEAD  
> **Primary management interface:** `sudo frpctl`  
> **Primary operating scale:** approximately `1–50 clients`, especially a few to a few dozen

## 2026-09-07 Consolidation Notice

이 문서는 세 개의 Product Master 계열 파일을 전수 비교하여 하나의 canonical 문서로 통합한 버전이다.

통합 원칙:

- 2026-09-04의 두 완전본은 SHA-256이 동일한 동일본이며, **제품 철학·아키텍처·범위·로드맵의 내용적 기준**으로 사용한다.
- 개발서버의 기존 `docs/PRODUCT_MASTER.md`는 이후 변경 사항 일부를 포함했지만, 다수 섹션 누락과 Markdown/content corruption이 확인되어 **그 자체를 기준본으로 사용하지 않는다**.
- 손상본에서 실제 코드/릴리스와 일치하는 신규 정보만 선별 병합한다.
- **버전, 릴리스, 브랜치, exact HEAD, 실제 capability 상태는 Git repository / release artifact / 테스트된 동작이 최종 기준**이다.
- 이 문서와 실제 Git 상태가 충돌하면 실제 Git/release/tested behavior가 우선한다.

현재 제품 방향의 핵심:

- 목표 규모는 **1~50 Clients**, 특히 few to a few dozen 중심이다.
- 대형 fleet orchestration, Web UI, Database, HA orchestrator는 현재 제품 목표가 아니다.
- official FRP만 사용하고 exact version으로 pin한다.
- 현재 published stable은 `v2.2.1`이며 pinned FRP는 `0.71.0`이다.
- `v2.2.0`은 FRP `0.71.0`을 처음 stable로 채택한 historical release이며, `v2.2.1`은 그 이후 hardening patch release다.
- Zero-Touch Short URL은 Option B(operator-owned reverse proxy + optional `bootstrap_hostname`) 모델로 `v2.1.3`에 stable 도입됐다.
- `public_hostname`은 published service용 optional user-facing alias이며 control identity가 아니다.
- Group은 몇십 대 관리를 위한 **Simple Manual Group + multiple membership + Tags + basic filters** 범위가 기준이다.
- macOS, Windows, Rocky 8/9, Amazon Linux 2023 등은 `v2.2.1` stable validation matrix에 포함된다. Amazon Linux 2와 PowerShell 7은 실제 validation level을 별도로 구분한다.

---

# 1. 문서의 목적

이 문서는 **FRP Auto Deploy 프로젝트의 최상위 제품 기준 문서**다.

다음 질문에 대한 최종 답은 이 문서를 기준으로 한다.

- 이 프로젝트가 해결하려는 문제는 무엇인가?
- 이 프로젝트는 어떤 제품인가?
- 무엇을 구현해야 하는가?
- 무엇은 구현하지 않는가?
- 사용자는 이 제품을 어떻게 사용해야 하는가?
- 서버와 클라이언트의 책임은 무엇인가?
- CLI는 어떤 원칙으로 설계되는가?
- Client / Service / Group / Tag의 관계는 무엇인가?
- 보안 모델은 어떻게 구성되는가?
- 기능 추가 시 어떤 원칙을 지켜야 하는가?
- 현재 어디까지 구현되었으며 앞으로 무엇을 개발할 것인가?

README, CLI Reference, Security 문서, Deployment Mode 문서 등 세부 문서는 이 문서를 보완한다.

제품 방향 또는 세부 문서 간 내용이 충돌할 경우:

1. 실제 코드와 테스트된 동작
2. 이 Product Master Document
3. 세부 기술 문서
4. README / 예제

순으로 확인한다.

단, 릴리즈 버전과 실제 구현 상태는 Git repository와 release artifact를 최종 기준으로 한다.

---

# 2. Product Charter

## 2.1 제품명

**FRP Auto Deploy**

---

## 2.2 제품 정의

FRP Auto Deploy는 공식 `fatedier/frp`를 수정하거나 fork하지 않고 그 위에 구축하는:

> **Lightweight FRP Deployment & Operations Layer**

이다.

보다 사용자 관점에서 정의하면:

> **방화벽 또는 NAT 뒤에 있는 서버와 서비스를 VPN이나 복잡한 NAT 설정 없이 외부에서 안전하고 쉽게 연결하고 관리하기 위한 Zero-Touch Remote Access Management 도구**

이다.

FRP 자체가 터널링 엔진이라면 FRP Auto Deploy는 그 위에서 다음을 담당한다.

- 설치
- 초기 등록
- 신뢰 수립
- Client identity
- Service 정의
- Public port 할당
- Zero-touch deployment
- Client inventory
- CLI 관리
- 서비스 lifecycle
- 업데이트
- 백업/복구
- 진단
- 감사
- Simple Group/Tag/Filter 기반 few-to-few-dozen 운영

즉:

```text
Official FRP
=
Tunnel Engine

FRP Auto Deploy
=
Deployment
+ Enrollment
+ Identity
+ Service Management
+ Port Management
+ Inventory
+ Operations CLI
+ Security Controls
+ Lifecycle Management
```


## 2.3 Target Operating Scale — 2026-09-04 Current Direction

FRP Auto Deploy는 수백~수천 대를 운영하는 Fleet Management 제품을 목표로 하지 않는다.

현실적인 target 규모는 다음과 같다.

```text
1~5 Clients
매우 쉬워야 함

10~30 Clients
편하게 관리 가능해야 함

30~50 Clients
Group / Tag / Filter 정도로 충분히 관리 가능

100~1000 Clients
현재 제품 목표 아님
```

즉 제품의 primary target은:

> **Small-to-medium remote access environment, typically a few systems to a few dozen clients.**

기존 문서의 “대규모 운영”, “수십~수백 Client” 같은 표현은 대형 fleet orchestration을 의미하는 것으로 해석하지 않는다. 현재 제품 방향에서는 **몇십 대까지의 단순하고 안전한 운영성**이 기준이다.

---

# 3. 해결하려는 문제

## 3.1 기존 원격접속의 문제

기업이나 고객 환경의 Linux 서버는 일반적으로 다음 환경에 존재한다.

```text
Internet
   ↓
Firewall / NAT
   ↓
Private Network
   ↓
Linux Server
```

외부에서 접근하려면 일반적으로 다음 방법이 필요하다.

- VPN
- 방화벽 NAT
- Port Forwarding
- Bastion Host
- 별도의 원격관리 제품
- 고객에게 방화벽 변경 요청
- Windows 원격지원 도구를 통한 우회 접근

특히 고객 또는 파트너에게 장애 지원을 제공할 때 문제가 커진다.

예:

```text
지원 엔지니어
     ↓
고객에게 VPN 계정 요청
     ↓
VPN Client 설치
     ↓
방화벽 정책 요청
     ↓
NAT / Port Forwarding
     ↓
고객 내부 서버 접속
```

소규모 환경이나 일시적인 기술지원에서는 이 과정이 지나치게 복잡하다.

---

# 4. 제품이 제공하는 해결 방식

FRP Auto Deploy는 공인 IP를 가진 하나의 FRP Server와 방화벽 뒤 Client 사이에 outbound tunnel을 생성한다.

```text
                     Internet

                         │
                         ▼
                ┌────────────────┐
                │ FRP Auto Deploy│
                │     Server     │
                │   Public IP    │
                └───────┬────────┘
                        │
                FRP Control Tunnel
                        │
       ┌────────────────┼────────────────┐
       │                │                │
       ▼                ▼                ▼
   Client A          Client B         Client C
   NAT/Firewall      NAT/Firewall     NAT/Firewall
```

Client는 Server로 outbound connection을 생성한다.

따라서 일반적으로 Client 측에서:

- inbound firewall opening
- NAT
- public IP
- DDNS

가 필요하지 않다.

---

# 5. 핵심 사용자 경험

제품의 핵심 UX는 다음 두 문장으로 표현한다.

> **Server는 한 번 설치한다.**

그리고:

> **Client는 한 줄로 연결하고 `frpctl` 하나로 관리한다.**

운영자는 이후 대부분의 작업을:

```text
sudo frpctl
```

에서 수행한다.

## 현재 Zero-Touch UX

### Linux stable path

`v2.1.3`부터 optional `bootstrap_hostname`과 operator-owned reverse proxy를 사용하는 **Option B Short URL**이 stable이다.

목표 형태:

```bash
curl -fsSL https://bootstrap.example.com/i/<ticket> | sudo bash
```

`bootstrap_hostname`이 없으면 기존 `zt1.` 기반 transitional package/fallback을 유지한다. Legacy long-form bootstrap도 backward compatibility를 위해 유지할 수 있다.

Short URL의 완전한 `/i/<ticket>` URL은 short-lived credential로 취급한다. Reverse proxy access log에는 `/i/` path를 기록하지 않거나 redaction하는 것을 권장한다.

### Windows stable path

Windows에서는 UX를 짧게 만들더라도 production path에서 다음을 금지한다.

```text
FORBIDDEN: download-and-pipe-directly-to-execution
```

현재 보안 계약은 다음이다.

```text
Short bootstrap URL
        ↓
PowerShell bootstrap file download
        ↓
Expected SHA256 verification
        ↓
powershell.exe -File
```

즉 **command length를 줄이되 hash-before-execute trust model을 약화하지 않는다.**

---

# 6. Product Principles

FRP Auto Deploy의 모든 기능은 다음 원칙을 따라야 한다.

## 6.1 Lightweight First

제품을 Kubernetes 기반 management platform이나 대형 RMM 시스템으로 만들지 않는다.

기본 운영 구성은:

```text
FRP Server
+
Small management layer
+
CLI
```

이다.

불필요한 구성요소를 추가하지 않는다.

---

## 6.2 CLI First

제품의 기본 관리 인터페이스는:

```text
sudo frpctl
```

이다.

현재 제품 방향에서는 다음을 기본 의존성으로 만들지 않는다.

- Web UI
- Database
- Dashboard
- 별도 Management Server

Client 수가 늘어나더라도 우선 CLI/TUI의 검색, 필터, 그룹, 자동화를 개선한다.

---

## 6.3 Zero-Touch First

일반적인 Client deployment는 가능한 한:

```text
Server에서 명령 생성
→
Remote Client에서 한 번 실행
→
자동 Enrollment
→
Identity 생성
→
Service 연결
```

이어야 한다.

단, Manual Enrollment도 계속 지원한다.


Zero-Touch의 목표는 단지 “한 줄”인 것이 아니라 **짧고 전달하기 쉬운 한 줄**이다. 긴 bootstrap parameter를 command line에 나열하는 대신 server-side enrollment state를 활용하는 방향을 우선한다.

---

## 6.4 Official FRP를 그대로 사용한다

FRP 자체를 fork하지 않는다.

```text
fatedier/frp
    ↓
official frps / frpc
    ↓
FRP Auto Deploy management layer
```

FRP 버전을 자동으로 최신 버전으로 따라가지 않는다.

반드시:

```text
Pinned
+
Tested
+
Validated
```

된 버전을 사용한다.

현재 상태:

```text
Current published stable FRP = 0.71.0
Current project stable        = 2.2.1
Historical v2.1.3 FRP        = 0.70.1
```

향후 FRP bump도 exact tested version으로 pin하며 자동으로 latest를 추적하지 않는다.

---

## 6.5 Fail Closed

보안, identity, registry, update, certificate 상태가 불명확한 경우 추측하여 계속 진행하지 않는다.

예:

```text
Unknown build
Unknown identity
Invalid signature
CA mismatch
Registry corruption
Ambiguous client selector
```

상태에서는 실패해야 한다.

---

## 6.6 Identity와 Display Metadata를 분리한다

Client identity는 hostname이나 IP가 아니다.

Canonical identity:

```text
CLIENT ID
=
immutable machine identity
```

다음 항목은 변경 가능한 metadata다.

```text
label
hostname
note
tags
groups
```

metadata 변경으로 identity가 바뀌어서는 안 된다.

---

## 6.7 Server-Owned Administration Metadata

다음 관리 정보는 Server가 authoritative source다.

```text
label
note
tags
group membership
public port reservations
management status
```

Client가 임의로 자신을 Production Group이나 특정 Customer Group에 넣을 수 있어서는 안 된다.

---

## 6.8 Preserve State

다음 작업으로 identity 또는 persistent port가 불필요하게 변경되어서는 안 된다.

- project update
- FRP update
- target host 변경
- target port 변경
- disable / enable
- reboot
- re-enrollment recovery where applicable

Public port는 사용자 입장에서 persistent resource로 취급한다.


---

## 6.9 Scope Discipline — Few-to-Few-Dozen First

제품 기능은 몇십 대 운영에 실제 필요한 수준까지만 확장한다. 다음은 현재 제품 목표가 아니다.

```text
Fleet orchestration
hundreds/thousands-client management
complex selector language
nested group hierarchy
canary rollout framework
large-scale staged deployment
bulk destructive management
automatic firewall management
automatic DNS provider management
Web UI / Database / Dashboard
HA orchestrator
```

새 기능이 이런 방향으로 제품 범위를 확장한다면 실제 field demand가 확인되기 전에는 추가하지 않는다.

---

# 7. Target Users

주요 사용자는 다음과 같다.

### 시스템 관리자

방화벽 뒤의 여러 Linux 서버를 원격 관리하려는 관리자.

### Technical Support Engineer

고객이나 파트너 서버에 일시적 또는 지속적으로 접속해야 하는 엔지니어.

### Partner / Customer Lab Administrator

별도의 VPN 인프라 없이 Lab 서버 접근을 제공하려는 사용자.

### Small Infrastructure Operator

NGROK 또는 복잡한 VPN/RMM 대신 자기 소유 FRP 서버를 운영하려는 사용자.

---

# 8. 대표 사용 시나리오

## 8.1 Client 자신의 SSH만 공개

```text
Internet
   ↓
FRP Server:6000
   ↓
Client A
   ↓
127.0.0.1:22
```

---

## 8.2 하나의 Client에서 여러 서비스 공개

```text
Client A

SSH
127.0.0.1:22
       ↓
Server:6000

HTTPS
127.0.0.1:443
       ↓
Server:6001
```

---

## 8.3 Client를 LAN Gateway처럼 사용

```text
Internet
   ↓
FRP Server
   ↓
FRP Client
   ├── 10.10.10.20:22
   ├── 10.10.10.30:80
   └── 10.10.10.40:443
```

Client에 서비스가 직접 실행되고 있을 필요는 없다.

Client가 접근 가능한 LAN의 다른 서버도 target으로 설정할 수 있다.

이 기능은 고객 환경에서 매우 중요한 활용 방식이다.

---

# 9. Service Model

현재 기본 Service Type은:

```text
SSH
HTTP
HTTPS
Custom TCP
```

이다.

내부적으로 모두 FRP TCP proxy 기반이다.

---

## 9.1 SSH

예:

```text
Target:
127.0.0.1:22

Public:
FRP-SERVER:6000
```

외부 접속:

```text
ssh -p 6000 user@FRP-SERVER
```

Zero-touch SSH에서는 반드시 기존 SSH login user를 명시적으로 받아야 한다.

제품은:

- OS 사용자 생성
- SSH key 생성
- `authorized_keys` 변경
- `sshd_config` 변경
- SSH Server 자동 설치

를 수행하지 않는다.

---

## 9.2 HTTP

HTTP application을 TCP 그대로 전달한다.

예:

```text
10.10.20.30:80
```

---

## 9.3 HTTPS

HTTPS 역시 TCP passthrough다.

Application TLS를 FRP Auto Deploy가 종료하지 않는다.

---

## 9.4 Custom TCP

예:

```text
Grafana       :3000
API           :8080
PostgreSQL    :5432
Appliance UI  :8443
```

등 TCP 기반 서비스를 사용할 수 있다.

---

# 10. Client Model

Client의 기본 구조:

```text
Client
│
├── Immutable Identity
│    └── CLIENT ID
│
├── Display Metadata
│    ├── label
│    ├── hostname
│    └── note
│
├── Classification
│    ├── tags
│    └── groups
│
├── Management Identity
│
└── Services
     ├── ssh
     ├── web-admin
     ├── api
     └── ...
```

한 Client는 여러 Service를 가질 수 있다.

---

# 11. Service Identity

Service는 stable Service ID를 사용한다.

예:

```text
ssh
web-admin
api
lan-router
```

Service ID는 rename하지 않는다.

예:

```text
Client ID + Service ID
```

조합으로 persistent service reservation을 식별할 수 있다.

---

# 12. Public Port Lifecycle

Public port는 단순 runtime 값이 아니라 persistent reservation이다.

## Disable

```text
Service publication = stopped
Public port          = reserved
```

다시 enable 하면 기존 port를 사용한다.

---

## Edit

Target을:

```text
127.0.0.1:22
```

에서:

```text
10.10.10.20:22
```

로 바꾸더라도 Public port를 유지한다.

---

## Release

```text
Service reservation 삭제
Public port pool 반환
```

이후 다른 Service가 해당 port를 사용할 수 있다.

---

# 13. Lifecycle Semantics

세 명령은 완전히 다른 의미를 가진다.

## Disable

```text
서비스 일시 중지
Port 유지
Identity 유지
```

## Release

```text
Port reservation 반환
```

## Revoke

```text
Client management identity 차단
Port reservation 유지
```

따라서:

```text
disable != release
release != revoke
revoke != delete
```

이다.

Client uninstall 역시 Server reservation을 자동으로 release하지 않는다.

---

# 14. Enrollment Model

두 가지 기본 Enrollment 방법을 유지한다.

## 14.1 Zero-Touch

권장 기본 방식.

```text
Server
  ↓
create enrollment / Zero-Touch profile
  ↓
Short-lived bootstrap ticket
  ↓
One-line command
  ↓
Remote Client
  ↓
Secure redeem
  ↓
Persistent Identity
  ↓
Configured Services
```

Bootstrap Ticket은 반드시:

- high entropy
- short-lived
- hashed-at-rest
- first-machine bound
- 성공 후 single-use
- revocable

이어야 한다.

### Server-side Enrollment Profile

짧은 bootstrap UX를 위해 필요한 metadata는 가능한 한 Server-side에 보관한다.

후보 정보:

```text
server/control endpoint
CA fingerprint
services
ssh user
label
expiration
bootstrap hostname
```

Client command line에는 가능한 한 ticket/short URL만 남긴다.

### Stable Short URL Trust Model

`v2.1.3` stable Linux path의 trust model:

```text
ZERO_TOUCH_SHORT_URL_TRUST_MODEL
= OPTION_B_EXTERNAL_REVERSE_PROXY
```

의미:

- operator가 DNS, public certificate, reverse proxy를 관리한다.
- FRP Auto Deploy는 `bootstrap_hostname`을 소비한다.
- private CA 기반 management trust는 유지한다.
- `GET /i/<ticket>` 자체는 ticket을 consume/bind하지 않으며, 실제 binding은 secure redeem 단계에서 수행한다.
- `bootstrap_hostname`이 없으면 transitional fallback을 유지한다.

## 14.2 Manual Enrollment Code

사용자가 직접 Enrollment Code를 입력하는 방식도 계속 지원한다.

특히 다음에 유용하다.

- Zero-Touch URL 전달이 적합하지 않은 환경
- 설치 시점에 service를 대화식으로 구성하려는 환경
- 운영자가 bootstrap flow를 직접 통제해야 하는 환경

Zero-Touch와 Manual Enrollment 모두 최종 persistent CLIENT ID / management identity model은 동일해야 한다.

---

# 15. Management Identity

Enrollment 이후 Client는 persistent management identity를 가진다.

현재 설계:

```text
ECDSA P-256
```

Private key는 Client 밖으로 나가지 않는다.

Server는 public identity와 management metadata를 관리한다.

Signed management operation에는:

- schema
- client identity
- operation
- timestamp
- nonce
- payload digest

등이 포함된다.

Replay 방어를 위해 nonce 및 clock window를 사용한다.

---

# 16. Deployment Modes

제품에는 두 개의 공식 deployment mode만 존재한다.

```text
Direct
Enterprise single-443
```

NAT는 deployment mode가 아니다.

---

## 16.1 Direct

기본 구성:

```text
TCP/443
FRP Control

TCP/6099
Enrollment / Management HTTPS

TCP/6000-6098
Published Services
```

Public port와 실제 listen port는 필요에 따라 분리할 수 있다.

---

## 16.2 Enterprise single-443

기업 네트워크에서 non-standard TLS connection이 reset되거나 TCP/443 사용이 요구되는 경우 사용한다.

```text
Public TCP/443
        │
        ├── HTTPS Enrollment
        │
        └── FRP Control over WSS
```

Internal:

```text
127.0.0.1:6099 allocator
127.0.0.1:7000 frps backend
```

6099와 7000을 Internet에 직접 공개하지 않는다.

Published service ports는 별도로 유지한다.


---

## 16.3 NAT / DNAT Topology

FRP Server가 firewall 뒤의 private IP에서 동작하고 firewall이 public IP를 DNAT하는 구성도 지원 대상이다. NAT는 deployment mode 자체가 아니라 외부 network topology다.

예:

```text
Internet
   |
203.0.113.10
Firewall / NAT
   | DNAT
10.10.10.10
FRP Auto Deploy Server
```

권장 방식은 service port의 의미를 유지하기 위해 1:1 port mapping을 사용하는 것이다.

```text
Public 6001 -> Internal 6001
```

다음처럼 외부/내부 port를 다르게 translation하면:

```text
Public 16001 -> Internal 6001
```

FRP Auto Deploy의 persistent public-port reservation과 실제 Internet endpoint의 의미가 달라질 수 있으므로 현재 product model에서는 권장하지 않는다.

---

# 17. Network Responsibility Boundary

FRP Auto Deploy가 자동으로 변경하지 않는 것:

- OCI Security List
- AWS Security Group
- external firewall
- NAT rule
- UFW
- firewalld
- iptables
- 고객의 SSH 계정
- SSH key
- SSH daemon configuration

이것은 의도적인 설계다.

## 17.1 DNS Provider Responsibility

FRP Auto Deploy는 DNS Provider가 아니다. 다음을 자동 수행하지 않는다.

```text
Route53 API
Cloudflare DNS API
automatic DNS A/AAAA record creation
DDNS lifecycle
ACME / Let's Encrypt lifecycle
```

관리자가 외부 DNS에서 필요한 record를 구성하고 FRP Auto Deploy는 hostname을 **소비하고 표시**한다.

## 17.2 bootstrap_hostname과 public_hostname은 다르다

두 hostname은 목적이 다르다.

```text
bootstrap_hostname
= Zero-Touch short bootstrap entrypoint
= operator reverse proxy / public TLS endpoint

public_hostname
= published service access용 optional user-facing alias
= SSH/HTTP/HTTPS/Custom TCP endpoint 표시용
```

둘 다 CLIENT ID나 control-plane identity가 아니다.

## 17.3 Public IP vs Public Hostname

Authoritative model:

```text
Public IP
= Primary infrastructure/control endpoint

Public Hostname
= Optional user-facing alias for published services
```

예:

```text
Public IP       = 203.0.113.10
Internal IP     = 10.10.10.10
Public Hostname = access.example.com
```

`public_hostname`은 다음을 변경하지 않는다.

```text
FRP control endpoint
allocator endpoint
CLIENT ID
Service ID
management identity
CA
public port reservation
```

## 17.4 IP fallback

Hostname이 설정되어도 infrastructure IP fallback은 항상 유지한다.

```text
ssh -p 6000 admin@access.example.com
ssh -p 6000 admin@203.0.113.10
```

## 17.5 Hairpin NAT / Split DNS

같은 내부 LAN에서 public hostname을 사용해 같은 firewall의 public IP로 되돌아가는 접속은 firewall의 hairpin NAT 지원 여부에 영향을 받을 수 있다. 이는 FRP Auto Deploy 자체 bug로 보지 않는다.

필요 시:

```text
Hairpin NAT
또는
Split DNS
```

를 사용한다.

## 17.6 NAT / DNAT responsibility

NAT topology는 지원할 수 있으나 network topology이며 deployment mode가 아니다. 가능하면 public service port와 internal FRP service port를 1:1 mapping하여 persistent public-port 의미를 유지한다.

---

# 18. CLI Product Specification

CLI의 canonical grammar:

```text
<verb> <resource> [target] [property] [value]
```

예:

```text
show clients

show client 24cd7856

set client 24cd7856 label branch-a

create enrollment

revoke client 24cd7856

release service 24cd7856 ssh
```

---

# 19. CLI UX Principles

## Persistent REPL

```text
sudo frpctl
```

로 persistent CLI에 진입한다.

---

## Tab Completion

Tab은:

- valid command
- resource
- CLIENT ID
- Service ID
- 향후 Group

을 completion 한다.

Tab 자체가 command를 실행해서는 안 된다.

---

## Context Help

```text
?
```

또는:

```text
help
help show
help set client
```

을 사용한다.

---

## Command History

History는 현재 session에만 유지한다.

민감한 command가 shell history에 장기간 남지 않도록 persistent CLI history를 파일로 저장하지 않는다.

---

## Shell Expansion 금지

CLI parser는:

- shell substitution
- wildcard expansion
- pipe
- command execution

등을 수행하지 않는다.

---

# 20. Canonical Client Selector

Canonical selector는:

```text
CLIENT ID
```

이다.

예:

```text
24cd7856
```

unique label이나 unique hostname을 직접 입력하는 shortcut은 허용할 수 있다.

그러나:

```text
hostname
IP
SSH connection string
```

을 identity로 사용하지 않는다.

Ambiguous selector는 반드시 fail closed 한다.


---

## 20.1 Public Hostname CLI / Display Semantics

Public Hostname의 canonical administrative operations는 다음 방향을 따른다.

```text
set server hostname <fqdn>
unset server hostname
```

`set server hostname`은 다음을 변경하지 않는다.

```text
FRP control endpoint
CLIENT ID
Service ID
public port
CA / management identity
```

hostname이 설정된 경우 `show`/`info` 계열 출력에서는 user-facing access endpoint로 hostname을 우선 표시할 수 있으며, Public IP fallback은 항상 유지한다.

예:

```text
ssh -p 6000 aella@access.example.com
ssh -p 6000 aella@203.0.113.10   # fallback

http://access.example.com:6001
http://203.0.113.10:6001          # fallback
```

HTTPS는 TCP passthrough이므로 target Web Server certificate가 해당 hostname을 cover해야 정상적인 browser certificate validation이 가능하다. FRP Auto Deploy가 application TLS certificate lifecycle을 자동 관리하지 않는다.

---

# 21. Client Metadata

현재 Client metadata:

```text
label
hostname
note
tags
```

### label

관리자가 지정하는 friendly display name.

### hostname

Client에서 관찰된 hostname.

### note

관리자 메모.

### tags

다차원 분류용 key/value metadata.

예:

```text
customer=acme
site=seoul
env=prod
role=gateway
cloud=oci
```

---

# 22. Group Management — Product Direction

Client 수가 증가하면 단순 `show clients`만으로 운영하기 어려워진다.

Group의 목적은 **few to a few dozen clients를 사람이 이해하고 관리하기 쉽게 정리하고 찾고 운영하는 것**이다.

Current model:

```text
Manual Group
+
Multiple Membership
+
Tags
+
Basic Filters
```

## Current Simple Group MVP

필수 범위:

```text
create/delete/rename group
description
multiple membership
show groups
show group
show client <ID> groups
show clients --group
persistence
audit
backup/restore preservation
```

Manual Group MVP는 `v2.2.0`에서 stable로 shipped 되었고 `v2.2.1`에서도 유지된다. 현재 stable release qualification에서 Group lifecycle, persistence, backup/restore, audit 및 관련 Real E2E가 검증됐다.

현재 core scope가 아닌 것:

```text
Dynamic Group
complex selector language
Group hierarchy
large-scale bulk mutation
canary rollout
fleet orchestration
```

Dynamic Group, System Group 확장, broad bulk operation은 실제 field demand가 확인될 때만 검토한다.

---

# 23. Group과 Tag의 차이

## Group

사람이 이해하고 관리하기 위한 Client collection.

예:

```text
customer-acme
pilot
migration-wave-1
vip-support
```

## Tag

Client의 속성.

예:

```text
customer=acme
site=seoul
env=prod
role=gateway
```

따라서:

```text
Group != Tag
```

이다.

---

# 24. Multiple Group Membership

한 Client는 여러 Group에 속할 수 있어야 한다.

예:

```text
acme-gw-01

Groups:
  customer-acme
  seoul
  production
  gateway
```

Group을 단일 `group` property로 구현하지 않는다.

---

# 25. Group Types

현재 product contract에서는 **Manual Group**이 authoritative required type이다.

## Manual Group — CURRENT

관리자가 직접 membership을 관리한다.

예:

```text
customer-acme
pilot
seoul-lab
```

한 Client는 여러 Manual Group에 속할 수 있다.

## Dynamic Group — OPTIONAL / LATER

Tag selector 기반 자동 membership은 장기 설계로 보존하지만 현재 required scope가 아니다.

실제 요구가 생긴다면 Tag가 source of truth이고 calculated membership을 중복 저장하지 않는 원칙을 유지한다.

## System Group — OPTIONAL / LATER

`all`, `ungrouped` 같은 system view는 필요성이 확인될 때 도입할 수 있다.

현재 Simple Group MVP의 release gate에 포함하지 않는다.

---

# 26. Status는 Group이 아니다

다음은 Group으로 구현하지 않는다.

```text
online
offline
legacy
revoked
```

이들은 Filter다.

예:

```text
show clients --status offline
```

---

# 27. Group CLI

목표 CLI:

```text
show groups

show group customer-acme

show group customer-acme clients

show client 24cd7856 groups

show clients --group customer-acme
```

Manual Group:

```text
create group customer-acme

set group customer-acme description "ACME customer systems"
```

Membership:

```text
add client 24cd7856 group customer-acme

remove client 24cd7856 group customer-acme
```

---

# 28. Dynamic Group CLI

**Status: OPTIONAL / LATER**

Dynamic Group CLI는 현재 제품의 필수 구현 요구사항이 아니다.

장기 후보 예:

```text
create group prod-seoul \
  --dynamic \
  --match-tag env=prod \
  --match-tag site=seoul
```

도입 시에도 초기 selector는 단순하게 유지하며, 복잡한 AND/OR/NOT expression language를 성급하게 만들지 않는다.

---

# 29. Filter Model

장기적으로 다음 조합을 지원한다.

```text
show clients --group customer-acme

show clients --tag env=prod

show clients --status offline

show clients \
  --group customer-acme \
  --tag role=gateway \
  --status online
```

초기 구현에서는 복잡한 expression language를 만들지 않는다.

필요가 확인된 후:

```text
AND
OR
NOT
```

selector 확장을 검토한다.

---

# 30. Group Enrollment

**Status: OPTIONAL / LATER**

Enrollment-time group assignment은 첫 Simple Group MVP의 필수 범위가 아니다.

현재 우선순위는:

```text
Manual Group CRUD
→ membership
→ persistence
→ audit
→ backup/restore
```

이다.

향후 필요 시:

```text
create enrollment --group customer-acme
```

같은 server-owned assignment를 추가할 수 있다. Client가 privileged Group metadata를 self-assign해서는 안 된다.

---

# 31. Group Internal Identity

Group name과 내부 identity를 분리한다.

예:

```text
Group ID:
grp_81ac7291

Name:
customer-acme
```

Group name 변경으로 membership이 깨지지 않아야 한다.

Client manual membership은 immutable Group ID를 저장한다.

Dynamic Group membership은 저장하지 않고 계산한다.

---

# 32. Group Output UX

기본:

```text
show clients
```

는 계속:

> **1 Client = 1 Row**

원칙을 유지한다.

Client가 여러 Group에 속한다고 Client row를 여러 번 반복하지 않는다.

예:

```text
CLIENT ID  LABEL        STATUS   GROUPS
24cd7856   acme-gw-01   online   ACME, Seoul, +2
```

Group 중심 조회는:

```text
show group ACME
```

에서 수행한다.

---

# 33. Group Bulk Operations

**Status: DEFERRED / DEMAND DRIVEN**

현재 target scale은 1~50 clients이므로 broad fleet operation은 core requirement가 아니다.

향후 반복 수요가 확인된 제한적 read-only/safe bulk operation 후보:

```text
doctor clients --group customer-acme
show services --group customer-acme
```

Mutation을 도입한다면 최소:

- target preview
- matched-client count
- confirmation
- per-client result
- partial-failure handling
- locking / idempotency
- audit

가 필요하다.

초기 Group implementation에서는 destructive bulk `revoke group`, `release group`을 지원하지 않는다.

---

# 34. Group Hierarchy

초기 버전에서는 Parent/Child nested group을 구현하지 않는다.

예:

```text
Korea
└── Seoul
    └── Customer A
```

같은 hierarchy는 다음 문제를 만든다.

- inheritance
- cycle
- precedence
- deletion dependency
- bulk scope ambiguity

현재는 Tag로 충분히 표현할 수 있다.

```text
country=kr
site=seoul
customer=acme
```

실제 운영 요구가 확인되면 추후 검토한다.

---

# 35. Inventory Model

장기적으로 Server inventory는 다음 관점을 제공한다.

```text
Clients
Services
Groups
Tags
Enrollments
Ports
Audit
```

예:

```text
FRP Server
│
├── Clients
│    ├── Client A
│    ├── Client B
│    └── Client C
│
├── Services
│
├── Groups
│
├── Enrollment Records
│
├── Port Reservations
│
└── Audit Events
```

---

# 36. Security Architecture

제품 보안은 FRP tunnel 인증과 management plane 인증을 분리한다.

## FRP Tunnel

- FRP native TLS 또는 WSS
- FRP token

## Management Plane

- HTTPS only
- Project private CA
- CA fingerprint bootstrap
- Enrollment secret
- Persistent ECDSA client identity
- nonce
- timestamp
- signed requests

FRP token을 management credential로 사용하지 않는다.

---

# 37. CA Model

Server가 project private CA를 생성한다.

개념:

```text
CA
 └── Server TLS Certificate
```

Client는 최초 bootstrap에서 CA fingerprint를 검증하고 이후 저장된 CA를 사용한다.

Plain HTTP fallback이나:

```text
curl -k
```

방식은 production enrollment path로 사용하지 않는다.

---

# 38. Secret Handling

다음 정보는 secret이다.

- FRP server token
- Enrollment Code
- Bootstrap Ticket
- Client private identity key
- Management MAC secret
- CA private key
- TLS private key
- token이 포함된 generated FRP config

CLI, Tab completion, `show` 명령, audit 등에 secret이 노출되어서는 안 된다.

---

# 39. Backup / Restore

Server의 핵심 state는 반드시 backup 대상이다.

최소:

```text
PKI
Server token
Project config
Client registry
```

필요에 따라:

```text
Enrollment metadata
Bootstrap state
Nonce state
```

도 포함한다.

Restore는 단순 파일 복사가 아니라:

```text
archive validation
snapshot
restore
service restart
doctor
rollback on failure
```

원칙을 따른다.

---

# 40. Doctor

`frpctl doctor`는 대표적인 문제 진단 도구다.

중요한 원칙:

> Doctor는 read-only다.

가능한 범위에서 다음을 확인한다.

- installation
- config
- PKI
- file permissions
- service state
- topology
- allocator
- FRP
- registry consistency
- network connectivity
- single-443 frontend
- TLS 문제
- port state

향후 Group이 추가되어도 Doctor의 기본 동작은 state를 변경하지 않는다.

---

# 41. Update Model

Project update와 upstream FRP update를 구분한다.

```text
update project
update frp
```

FRP는 무조건 latest를 설치하지 않는다.

```text
Pinned Version
↓
Compatibility Test
↓
Release Validation
↓
Adoption
```

순서를 따른다.

Update로 다음 정보가 사라져서는 안 된다.

- Client identity
- CA
- server token
- Client registry
- public port reservations
- Group
- Tags

---

# 42. Build / Release Integrity

같은 Project Version이라도 다른 build일 수 있으므로 `PROJECT_VERSION`만으로 동일성을 판단하지 않는다.

가능하면 다음을 함께 사용한다.

```text
release channel
immutable git ref
verified SHA256
bundle identity
exact source HEAD
```

Unknown build identity를 자동으로 "already up to date"로 판정하지 않는다.

## Current release integrity model

Current `v2.2.1` release manifest 기준:

```text
SHA256SUMS verification
exact pinned upstream FRP artifacts
source/dist parity
immutable stable tag reference
secret scan
```

을 사용한다.

현재 `signing=false`이며 SHA256SUMS는 integrity hash이지 독립적인 cryptographic release signature가 아니다. 이는 알려진 residual supply-chain risk다.

향후 후보:

```text
GitHub tag protection / rulesets
optional signed checksums
optional GitHub artifact attestation
```

단, v2.2.0 release를 위해 복잡한 long-lived signing PKI를 새로 도입하지 않는다. 구현한다면 GitHub-native, least-privilege 방식이 우선이다.

## FRP compatibility gate

FRP version bump는 반드시 fail-closed여야 한다.

```text
download
→ trusted expected digest 확보
→ SHA256 compare
→ mismatch면 즉시 FAIL
→ verified archive만 extract
→ verified binary만 execute
→ version/config/runtime compatibility
→ 모든 required check 성공 후 PASS report를 atomic하게 생성
```

stale PASS report나 다른 FRP version의 report를 재사용해서는 안 된다.

---

# 43. Audit

관리 operation은 가능한 한 audit 가능해야 한다.

예:

- Enrollment creation/revocation
- Client revoke
- Port release
- metadata 변경
- 향후 Group membership 변경
- Group creation/deletion
- Bulk operation
- Update / restore

Group 기능 도입 시 다음 event가 추가되어야 한다.

```text
group_created
group_updated
group_deleted
group_member_added
group_member_removed
```

Dynamic membership 계산 결과 자체를 모든 계산마다 audit하지는 않는다.

---

# 44. Product Scope — Current Core

현재 제품의 핵심 범위:

### Platform

- Linux FRP Server
- Linux/systemd Client stable baseline
- selected additional stable client platforms validated by the v2.2.1 release matrix

### Connectivity

- TCP
- SSH
- HTTP
- HTTPS passthrough
- Custom TCP
- LAN target publishing

### Management

- Enrollment
- Zero-Touch
- persistent CLIENT ID
- multi-service
- persistent public port
- metadata / tags
- Simple Manual Group MVP
- CLI
- Doctor
- Audit
- Backup / Restore
- Update
- Release / Revoke

### Deployment

- Direct
- Enterprise single-443
- public/listen port split
- external NAT/DNAT topology

### Friendly access

- `bootstrap_hostname`: stable Short URL entrypoint in v2.1.3
- `public_hostname`: stable user-facing published-service alias
- IP fallback preserved

Stable capability와 portability/CI-only capability를 혼동하지 않는다.

---

# 45. Explicit Non-Goals / Deferred Scope

다음 기능을 제품 핵심 범위에 자동으로 추가하지 않는다.

## Web UI

현재 계획 없음.

Client 증가 문제는 우선:

```text
Groups
Tags
Filters
CLI/TUI
```

로 해결한다.

---

## Database

현재 runtime requirement로 도입하지 않는다.

현재 lightweight state model을 유지한다.

---

## Dashboard / Monitoring Platform

Prometheus/Grafana/RMM 형태의 monitoring platform을 제품으로 만들지 않는다.

---

## HA Orchestrator

다중 FRP Server cluster orchestration은 현재 핵심 범위가 아니다.

---

## Automatic Firewall Management

하지 않는다.

---

## SSH Account / Key Management

하지 않는다.

---

## Every FRP Feature

FRP의 모든 기능을 UI/CLI로 감싸는 것이 프로젝트 목적이 아니다.

실제 Remote Access 운영에 필요한 subset에 집중한다.

---

## UDP

현재 core scope가 아니다.

실제 요구가 확인되면 별도 설계한다.


---

## Current Explicit Non-Goals Added 2026-09-04

다음은 현재 제품 목표가 아니다.

```text
hundreds/thousands-client fleet management
fleet orchestration
complex dynamic group selectors
nested group hierarchy
large-scale staged deployment
canary rollout framework
bulk destructive management
automatic DNS provider management
automatic TLS certificate lifecycle
```

몇십 대 운영을 위해 필요한 단순 Group/Tag/Filter와 위 항목들을 구분한다.

---

# 46. Windows Direction

Windows Server에서 `frps`를 제공하는 것은 현재 목표가 아니다. Windows는 Client platform으로 다룬다.

## Windows Client — STABLE

Stable implementation scope:

- PowerShell bootstrap
- persistent identity
- `frpc.exe`
- SSH
- HTTP / HTTPS passthrough
- Custom TCP
- LAN gateway
- service lifecycle CLI
- SYSTEM scheduled task/autostart
- reboot persistence
- LocalMachine-scoped credential protection where applicable

Security rule:

```text
never irm | iex in production Zero-Touch
```

Short URL bootstrap은 hash-before-execute를 유지한다.

Validation truth must distinguish:

```text
PowerShell 5.1 real-host E2E
PowerShell 7 CI/automated validation
PowerShell 7 same real host (only if pwsh exists)
```

## macOS Apple Silicon — STABLE

macOS client는 launchd 기반으로 관리한다.

Test management용 Reverse SSH는 FRP product path가 아니다.

```text
Reverse SSH = management/rescue path
FRP         = product path
```

Reverse SSH 성공만으로 FRP E2E PASS를 선언하지 않는다.

macOS CLI는 Python `readline` backend 차이를 고려하여 GNU Readline과 libedit/editline 모두에서 Tab completion UX가 동일해야 한다. Real PTY regression test를 macOS CI에 포함한다.

## Stable qualification rule

Windows/macOS는 `v2.2.1`에서 stable qualification을 완료했다. 이후 release에서도 실제 install/update/reboot/public connectivity/identity preservation contract를 regression gate로 유지한다.

---

# 47. Operating Environment Strategy

지원 상태는 반드시 다음을 구분한다.

```text
Code supported
Container tested
Systemd tested
Real VM / Physical host tested
Field validated
Stable release supported
```

한 단계 PASS가 다음 단계를 자동 의미하지 않는다.

## Current stable validation matrix

현재 `v2.2.1` stable qualification 결과:

| Platform | Validation level |
|---|---|
| Ubuntu 24 physical | Real E2E validated |
| Rocky Linux 8.10 | Real E2E validated |
| Rocky Linux 9.4 | Real E2E validated, including legacy upgrade/fresh install coverage |
| Amazon Linux 2023 | Real E2E validated |
| Amazon Linux 2 | Container/CI portability only; no live Real E2E host |
| macOS Apple Silicon | Real E2E validated, including launchd/reboot/libedit PTY completion |
| Windows 10 / PowerShell 5.1 | Real E2E validated, including SYSTEM task/reboot |
| PowerShell 7 | CI validated; same-host Real E2E only when `pwsh` is actually available |

`v2.2.1` release qualification completed Double Full Real E2E on qualified candidate `2140be5b...`; release commit `19d4b6fb...` is tree-identical.

특히 별도 validation이 필요한 환경:

- SELinux Enforcing
- Amazon Linux 2 legacy OpenSSL/systemd
- ARM64
- 실제 DNAT topology
- sleep/wake가 있는 mobile macOS environment

환경 blocker와 product defect를 구분한다.

---

# 48. OCI Reference Deployment

OCI Free Tier는 FRP Server의 좋은 reference deployment다.

목표 사용 패턴:

```text
OCI Free Tier
+
Reserved Public IP
+
FRP Auto Deploy Server
```

장점:

- 고정 Public IP
- 낮은 비용
- 항상 접근 가능한 Internet endpoint
- 소규모 FRP traffic에 적합

그러나 OCI 자체의:

- Security List
- VCN
- subnet
- public IP
- routing

은 FRP Auto Deploy가 자동 관리하지 않는다.

OCI deployment는 제품의 reference environment이지 제품 자체의 필수 구성요소는 아니다.

---

# 49. Success Criteria

제품이 성공했다고 볼 수 있는 핵심 기준:

## Deployment

새 Client를 짧은 시간 안에 안전하게 등록할 수 있다.

## Simplicity

관리자가 대부분의 일상 작업을:

```text
sudo frpctl
```

하나로 수행할 수 있다.

## Stability

Update 또는 reboot 후에도:

- Identity
- Port
- Services

가 유지된다.

## Recoverability

Backup / restore / doctor로 운영 상태를 복구할 수 있다.

## Scalability of Operations

Client 수가 수십~수백 대로 증가해도:

```text
Group
Tag
Filter
Bulk Operation
```

으로 관리할 수 있다.


> **2026-09-04 Current Scope Clarification:** 위 “수십~수백” 문구는 이전 roadmap 표현이다. 현재 authoritative success target은 **1~50 Clients, 특히 10~30 Clients를 편하게 관리하고 30~50 Clients를 Group/Tag/Filter로 정리할 수 있는 수준**이다. Bulk Operation은 성공 기준의 필수 요소가 아니며 demand-driven이다.

## Zero-Touch Usability

고객/파트너에게 전달하는 Zero-Touch bootstrap은 보안 검증을 유지하면서도 실사용상 짧고 복사하기 쉬워야 한다.

## Friendly DNS Access

관리자가 외부 DNS를 구성한 경우 published SSH/HTTP/HTTPS/Custom TCP endpoint를 Public Hostname으로 이해하기 쉽게 사용할 수 있어야 하며 IP fallback이 유지되어야 한다.

## Security

보안을 쉽게 하기 위해:

- TLS verification
- identity verification
- secret protection

을 우회하지 않는다.

---

# 50. Current Product Status

## 50.1 Published Stable

현재 GitHub published stable:

```text
Project:              2.2.1
Tag:                  v2.2.1
FRP:                  0.71.0
Release commit:       19d4b6fb8a9bee2d477ace6f5c3ed70310e7ea8f
Qualified candidate:  2140be5b6342c3651c16a458f8ea1bc9b577d992
Candidate/release:    tree-identical
Double Full Real E2E: PASS / PASS
```

`v2.2.1` 주요 사항:

- official FRP `0.71.0` exact pin 유지
- macOS libedit/editline `frpctl` Tab completion hardening
- FRP compatibility gate fail-closed hardening
- public documentation metadata sanitization/scanner
- post-v2.2.0 correctness/documentation hardening
- Ubuntu 24 / Rocky 8 / Rocky 9 / AL2023 / macOS / Windows Real E2E
- Amazon Linux 2 portability/CI validation
- Simple Manual Group MVP
- Public Hostname / DNS alias
- Zero-Touch Short URL Option B
- identity/service/public-port preservation

Stable Short URL trust model:

```text
OPTION_B_EXTERNAL_REVERSE_PROXY
```

Windows production Zero-Touch contract:

```text
download
→ SHA256 verify
→ powershell.exe -File
```

Never production `irm | iex`.

## 50.2 Main

Release 시점의 `main`과 `v2.2.1` tag target은:

```text
19d4b6fb8a9bee2d477ace6f5c3ed70310e7ea8f
```

이다.

문서-only maintenance commit은 release tag를 움직이지 않고 이후 `main`만 advance할 수 있다.

## 50.3 Historical v2.2.0 Release

`v2.2.0`은 historical stable milestone이다.

```text
Project: 2.2.0
FRP:     0.71.0
Release commit:
04a2474c6f3b83f444341752bfd6c4a500480556
```

주요 의미:

- first stable release on FRP `0.71.0`
- Double Full Real E2E
- macOS / Windows / Simple Manual Group / Public Hostname qualification

Published `v2.2.0`은 immutable하며 retag/rewrite하지 않는다.

## 50.4 v2.2.1 Hardening Candidate History

```text
Candidate:
2140be5b6342c3651c16a458f8ea1bc9b577d992

Final release commit:
19d4b6fb8a9bee2d477ace6f5c3ed70310e7ea8f

Candidate/release tree:
tree-identical
```

Final qualification:

```text
FULL_REAL_E2E_PASS_1=PASS
FULL_REAL_E2E_PASS_2=PASS
PASS_HEADS_IDENTICAL=YES
MACOS_REAL_LIBEDIT_COMPLETION=PASS
AL2_PORTABILITY=PASS
OWNER_MANUAL_E2E_REQUIRED=NO
```

## 50.5 Current Release Rule

현재 runtime/release work는 closed 상태다.

```text
CURRENT_STABLE=2.2.1
PINNED_FRP=0.71.0
UNRESOLVED_RELEASE_BLOCKERS=0
NEW_RELEASE_REQUIRED_FOR_DOCS_ONLY_CHANGE=NO
NEW_TAG_REQUIRED_FOR_DOCS_ONLY_CHANGE=NO
NEW_DOUBLE_FULL_REAL_E2E_REQUIRED_FOR_DOCS_ONLY_CHANGE=NO
```

Release 이후 code/runtime 변경이 필요하면 이미 published 된 tag를 움직이지 않고 새로운 patch release를 사용한다.

---

# 51. Main / Development State

현재 release line은 `v2.2.1`로 closed 상태이며 별도의 open release candidate를 current stable처럼 취급하지 않는다.

```text
Published Stable = v2.2.1
Pinned FRP       = 0.71.0
Release commit   = 19d4b6fb8a9bee2d477ace6f5c3ed70310e7ea8f
```

`v2.2.1`에 포함된 주요 capability:

- canonical `frpctl` grammar / REPL hardening
- GNU Readline + macOS libedit completion portability
- Client ID selector hardening
- `public_hostname` alias
- macOS / Windows clients
- Simple Manual Group MVP
- sync/reconcile and apply hardening
- install/uninstall/rollback correctness
- FRP compatibility gate hardening
- FRP `0.71.0` exact pin
- expanded Real E2E harness / platform matrix
- documentation and public-metadata hardening

Master에서 capability status를 표시할 때 반드시 `STABLE`, `MAIN`, `TESTED-ONLY`, `DEFERRED`를 구분한다.

# 52. Capability Status Labels

앞으로 모든 roadmap 항목은 다음 상태 중 하나로 관리한다.

### STABLE

Stable release에 포함되고 검증됨.

### MAIN

`main`에는 구현되었으나 아직 다음 Stable release에 포함되지 않음.

### IN PROGRESS

branch 또는 development 작업 중.

### PLANNED

설계 또는 개발이 합의되었으나 구현 전.

### DEFERRED

현재 우선순위가 아님.

### OUT OF SCOPE

제품 방향과 맞지 않음.

---

# 53. Product Roadmap

---

## Phase 0 — FRP Deployment Foundation

**Status: STABLE**

목표:

> 공식 FRP를 쉽게 설치하고 안정적으로 운영한다.

포함:

- frps/frpc install
- version pinning
- service management
- public port allocation
- Linux lifecycle
- rollback fundamentals

---

# 54. Phase 1 — Secure Management Foundation

**Status: STABLE**

목표:

> 단순 FRP script에서 안전한 관리 제품으로 발전.

포함:

- HTTPS-only enrollment
- private CA
- CA fingerprint bootstrap
- Enrollment Code
- persistent management identity
- signed requests
- replay defense
- Bootstrap Ticket
- Zero-touch deployment
- registry
- audit
- doctor
- backup/restore

---

# 55. Phase 2 — Multi-Service & Operational CLI

**Status: STABLE**

목표:

> 일상 운영을 `frpctl` 하나로 통합한다.

Stable/core:

- SSH / HTTP / HTTPS / Custom TCP
- multiple services
- LAN target
- persistent ports
- add/edit/disable/enable
- release/revoke distinction
- metadata/tags
- CLIENT ID selector
- contextual help
- shell-safe parser
- Zero-Touch

### P2.A — Zero-Touch Short URL

**Status: STABLE in v2.1.3 (Linux/systemd path)**

```text
Server-side bootstrap state
+
short /i/<ticket> URL
+
Option B external reverse proxy
```

`bootstrap_hostname`은 optional이며 없으면 transitional fallback을 유지한다.

### P2.B — Public Hostname / DNS Alias

**Status: STABLE in v2.2.0+**

```text
Public IP       = infrastructure/control primary
Public Hostname = optional published-service alias
IP fallback     = always preserved
DNS provider    = administrator responsibility
```

Canonical CLI:

```text
set server hostname <fqdn>
unset server hostname
```

### P2.C — Cross-platform REPL UX

**Status: STABLE in v2.2.1**

macOS libedit와 GNU Readline 모두에서 Tab completion contract를 동일하게 유지하고 PTY regression으로 검증한다.

---

# 56. Phase 3 — Group & Fleet Management

**Status: STABLE — SIMPLE MANUAL GROUP MVP**

현재 제품에서 “Fleet Management”는 대형 orchestration을 뜻하지 않는다.

목표:

> 1~50 clients, 특히 10~30 / 30~50 client 환경을 CLI에서 정리하고 찾기 쉽게 한다.

Required MVP:

```text
Manual Group
immutable Group ID
name / description
multiple membership
Tags
basic filters
persistence
audit
backup/restore
```

Manual Group MVP는 `v2.2.0`에서 shipped 되었고 `v2.2.1` release qualification에서도 실제 lifecycle/persistence/audit/backup-restore 동작이 검증됐다.

Not required now:

```text
Dynamic Group
System Group expansion
nested hierarchy
complex selector language
fleet-wide destructive operations
canary/staged rollout
```

제품 이름이나 roadmap에서 Group을 이유로 대형 fleet product처럼 확장하지 않는다.

---

# 57. Phase 4 — Safe Fleet Operations

**Status: DEFERRED / DEMAND DRIVEN**

몇십 대 운영에서 반복적으로 필요한 제한적 safe operation만 향후 검토한다.

후보:

```text
doctor clients --group ...
show services --group ...
```

Mutation은 preview/confirmation/per-client result/audit/idempotency가 전제다.

Broad destructive bulk operation은 현재 roadmap이 아니다.

---

# 58. Phase 5 — Controlled Rollout

**Status: DEPRIORITIZED / NOT CURRENT PRODUCT SCOPE**

Pilot/production canary framework, staged update orchestration 등은 대형 fleet 운영 성격이 강하므로 현재 제품 목표가 아니다.

실제 field demand가 명확해질 때만 재평가한다.

---

# 59. Phase 6 — Additional Platform Support

**Status: STABLE / PLATFORM-SPECIFIC VALIDATION**

Selected client platforms:

```text
Ubuntu 24 physical
Rocky Linux 8.10
Rocky Linux 9.4
Amazon Linux 2023
Amazon Linux 2 portability
macOS Apple Silicon
Windows 10
```

현재 `v2.2.1`에서 Ubuntu 24 physical, Rocky 8.10, Rocky 9.4, Amazon Linux 2023, macOS Apple Silicon, Windows 10/PS5.1은 Real E2E validated다. Amazon Linux 2는 live host 없이 Container/CI portability만 검증됐으며 PowerShell 7은 CI validated로 구분한다.

### Linux

Linux/systemd가 stable foundation이다.

### macOS

launchd, Apple Silicon, reboot/autostart, CLI PTY behavior를 검증한다.

### Windows

PowerShell bootstrap, SYSTEM task, lifecycle CLI, reboot/autostart를 검증한다.

### ARM64

Artifact support와 실제 environment validation을 구분한다.

### Additional Linux

실제 VM/host + security mode를 기준으로 지원 범위를 확장한다.

---

# 60. Phase 7 — Optional Protocol Expansion

**Status: DEFERRED**

실제 필요가 발생할 때 검토:

- UDP
- additional FRP proxy types

FRP가 지원한다는 이유만으로 자동으로 추가하지 않는다.

---

# 61. 기능 우선순위 판단 기준

새 기능을 제안할 때 다음 순서로 평가한다.

### 1. 실제 운영 문제인가?

실제 사용자가 반복적으로 겪는 문제인가?

### 2. Lightweight 원칙을 유지하는가?

Web platform이나 별도 infrastructure가 필요한가?

### 3. `frpctl` UX를 개선하는가?

제품을 더 단순하게 만드는가?

### 4. State consistency를 해치지 않는가?

Identity / Port / Registry에 새로운 ambiguity를 만드는가?

### 5. Security boundary를 약화시키지 않는가?

편의를 위해 trust model을 우회하는가?

### 6. 기존 기능으로 해결 가능한가?

Tag/Group/Filter로 가능한데 새로운 abstraction을 만드는 것은 아닌가?

---

# 62. Architecture Guardrails

향후 Coding AI 또는 개발자는 다음을 위반해서는 안 된다.

## FRP Fork 금지

공식 upstream binary 유지.

## Automatic Latest FRP 금지

Pinned/Tested 원칙.

## Web UI를 기본 요구사항으로 추가 금지

별도 제품 결정 없이는 CLI First 유지.

## Client Self-Assigned Privileged Metadata 금지

Group/관리 metadata는 Server-owned.

## Identity를 hostname/IP에 연결 금지

CLIENT ID 유지.

## Disable 시 Port Release 금지

Lifecycle semantics 유지.

## Update 시 Re-enrollment 요구 금지

정상 update는 identity를 유지해야 한다.

## Secret 출력 금지

show/help/Tab/audit에서 secret 노출 금지.

## 자동 Firewall 변경 금지

Network responsibility boundary 유지.

---

# 63. Testing Strategy

새 기능은 최소 다음 계층으로 검증한다.

```text
Unit
↓
Integration
↓
CLI / PTY
↓
Lifecycle
↓
Upgrade
↓
Distribution Matrix
↓
Real Environment
```

## Real E2E Harness

Repository의 Real E2E는 가능한 한 repeatable harness를 사용한다.

```text
tests/run-real-e2e.sh
```

핵심 요구:

```text
unique RUN_ID
step PASS/FAIL
timeouts
host identity checks
secret redaction
reboot reconnect handling
deterministic cleanup
repeatability
logs/reports
```

Ad-hoc SSH는 환경 조사/실패 진단에 사용하며, 관리용 reverse SSH 성공을 FRP product PASS로 간주하지 않는다.

## Final Double Full Real E2E Rule

Release candidate는 **동일 exact HEAD**에서 전체 E2E를 두 번 수행한다.

```text
FULL_REAL_E2E_PASS_1=PASS
FULL_REAL_E2E_PASS_2=PASS
PASS1_HEAD == PASS2_HEAD
```

PASS 사이 product code가 바뀌면:

```text
PASS_COUNTER=0
```

으로 reset한다.

## Current Real Platform Matrix

가능한 모든 실제 environment를 사용한다.

```text
Ubuntu 24 physical
Rocky Linux 8.10
Rocky Linux 9.4
Amazon Linux 2023
Amazon Linux 2 container/CI when no live host
macOS Apple Silicon
Windows 10
```

각 applicable platform에서 가능한 범위의:

```text
install
Zero-Touch
upgrade
identity preservation
service ID / public port preservation
actual SSH
actual HTTP
internal target
status/info/doctor
reboot/autostart
uninstall/reinstall
```

를 검증한다.

## FRP Version Upgrade Validation

FRP bump는 단순 new/new만 검사하지 않는다.

```text
old server / old client baseline
new server / old client
old server / new client where supported
new server / new client
rollback/failure path
```

mixed-version rolling upgrade의 실제 tunnel continuity와 no-reenrollment를 검증한다.

## public_hostname

각 full pass에서:

```text
set
sync
hostname access
unset
sync
IP fallback
re-set
sync
```

를 검증하고 control endpoint / identity / port가 변하지 않음을 확인한다.

## Group

Current Simple Group test matrix:

- CRUD
- rename/description
- multiple membership
- duplicate/nonexistent handling
- persistence
- reboot
- update
- backup/restore
- audit
- Tab/help/ambiguous input
- malicious shell-like input
- client self-assignment prohibition

Dynamic Group tests는 해당 기능이 실제 scope에 들어올 때만 required gate가 된다.

## macOS CLI PTY

macOS CI에는 실제 readline backend에서 최소:

```text
statu<Tab> → status
```

같은 PTY completion regression을 포함한다.

## Windows

PS5.1 real host와 PS7 CI를 구분해 기록한다. 실제 pwsh가 없는 host에서 PS7을 억지로 real-host PASS 처리하지 않는다.

## Failure Classification

Real E2E failure는 최소 다음 중 하나로 분류한다.

```text
PRODUCT_BUG
PLATFORM_COMPATIBILITY_BUG
DNS_IMPLEMENTATION_BUG
TEST_HARNESS_BUG
ENVIRONMENT_BLOCKER
UNSUPPORTED_PLATFORM_SCOPE
```

문제가 없는데 억지로 bug를 만들지 않는다.

---

# 64. Documentation Structure

권장 문서 구조:

```text
README.md
    │
    ├── Quick Start
    └── Product Overview

docs/
├── PRODUCT_MASTER.md
│
├── CLI_REFERENCE.md
├── SECURITY.md
├── DEPLOYMENT_MODES.md
├── FRP_UPGRADE.md
├── RELEASE_VALIDATION.md
├── RELEASE_CHECKLIST.md
└── OCI_ACCEPTANCE.md
```

`PRODUCT_MASTER.md`가 제품 설계의 최상위 기준이다.

---

# 65. README와 Master Document의 역할

## README

사용자가 빠르게 이해하는 문서.

답해야 하는 질문:

```text
이게 뭐지?
왜 쓰지?
어떻게 설치하지?
어떻게 Client를 붙이지?
```

## PRODUCT_MASTER

개발자와 Product Owner가 보는 문서.

답해야 하는 질문:

```text
왜 이렇게 설계했는가?
어디까지 제품 범위인가?
어떤 개념이 authoritative한가?
다음에는 무엇을 개발하는가?
```

README에 모든 내부 설계를 넣지 않는다.

---

# 66. Decision Log 관리

큰 제품 결정은 이 문서 하단에 기록한다.

형식:

```text
YYYY-MM-DD
Decision:
Reason:
Impact:
```

---

# 67. 현재 주요 Product Decisions

## 2026-08 — Official FRP Layer

**Decision**  
FRP를 fork하지 않고 official binary 위에 운영 layer를 제공한다.

**Reason**  
Upstream 호환성과 유지보수성을 유지한다.

---

## 2026-08 — CLI First

**Decision**  
Web UI/DB보다 `sudo frpctl`을 제품 중심 interface로 유지한다.

---

## 2026-08 — CLIENT ID First

**Decision**  
hostname/IP 대신 immutable CLIENT ID를 canonical identity로 사용한다.

---

## 2026-08 — Zero-Touch + Manual Enrollment

**Decision**  
Zero-Touch를 기본 UX로 제공하되 Manual Enrollment도 유지한다.

---

## 2026-08 — Multi-Service Client / LAN Gateway

**Decision**  
한 Client는 여러 TCP service를 publish할 수 있고 Client가 접근 가능한 LAN target도 service로 제공할 수 있다.

---

## 2026-08 — Enterprise single-443

**Decision**  
기업 firewall 환경을 위해 HTTPS enrollment와 FRP WSS control을 single TCP/443 mode로 제공할 수 있다.

---

## 2026-09 — Few-to-Few-Dozen Product Scale

**Decision**  
현실적인 target을 1~50 Clients로 명확히 한다.

**Impact**  
Fleet orchestration, nested groups, broad bulk mutation, canary framework는 현재 scope가 아니다.

---

## 2026-09 — Public Hostname as Optional User-Facing Alias

**Decision**  
Public IP는 infrastructure/control primary이며 `public_hostname`은 published-service용 optional alias다.

---

## 2026-09 — Simple Group Scope

**Decision**  
Manual Group + multiple membership + Tags + basic filters를 current Group scope로 한다.

---

## 2026-09 — Zero-Touch Short URL Option B

**Decision**  
`v2.1.3`에서 optional `bootstrap_hostname` + operator-owned reverse proxy 기반 Short URL을 stable로 채택한다.

**Impact**  
DNS/TLS/reverse proxy lifecycle은 operator-owned이며 private CA management trust를 유지한다.

---

## 2026-09 — Windows Bootstrap Hash-Before-Execute

**Decision**  
Windows production Zero-Touch에서 `irm | iex`를 사용하지 않는다.

**Impact**  
Short URL UX에서도 download → SHA256 verify → `powershell.exe -File` 순서를 지킨다.

---

## 2026-09 — Double Full Real E2E Release Gate

**Decision**  
최종 candidate는 동일 exact HEAD에서 전체 Real E2E를 2회 통과해야 한다.

**Impact**  
중간 code change 발생 시 pass counter를 0으로 reset한다.

---

## 2026-09 — FRP 0.71.0 Stable Adoption

**Decision**  
`v2.2.0`에서 official FRP `0.71.0`을 exact pin으로 stable 채택했고, `v2.2.1`에서도 동일 pin을 유지한다. 향후 bump는 별도 compatibility qualification을 요구한다.

---

## 2026-09 — Single Canonical Product Master

**Decision**  
앞으로 Product Master는 repository의 `docs/PRODUCT_MASTER.md` 하나만 canonical living document로 관리한다.

**Reason**  
복수 파생본으로 인한 상태 drift와 문서 corruption을 방지한다.

---

## 2026-09 — v2.2.1 Post-v2.2.0 Hardening Release

**Decision**  
이미 published 된 `v2.2.0`을 rewrite/retag하지 않고 hardening 변경을 `v2.2.1` patch release로 제공한다.

**Impact**  
`v2.2.1`은 FRP `0.71.0` pin을 유지하며 macOS libedit completion, FRP compatibility gate fail-closed, public metadata/docs hardening 및 correctness fixes를 포함한다. Double Full Real E2E를 동일 exact candidate HEAD에서 통과했다.

---

# 68. Near-Term Development Priority

현재 authoritative priority:

```text
1. Canonical Product Master를 GitHub main의 docs/PRODUCT_MASTER.md와 동기화
2. v2.2.1 field usage에서 실제 반복 문제가 발견될 때만 안정화
3. 새로운 기능은 1–50 client 운영 문제를 실제로 해결할 때만 검토
4. future FRP bump는 explicit compatibility qualification 후에만 진행
```

현재 runtime/release blocker는 없다.

Dynamic Group, broad Safe Fleet Operations, Controlled Rollout, Web UI/DB/HA 등으로 범위를 자동 확장하지 않는다. Group MVP 이후 우선순위는 **실사용 안정성/단순성 유지**다.

새 기능은 1~50 client 환경의 실제 반복 문제를 해결할 때만 추가한다.

# 69. 제품의 장기 모습

FRP Auto Deploy의 목표는 거대한 Remote Management Platform이 아니다.

장기적인 모습은 다음과 같다.

```text
                   Internet
                       │
                       ▼
             ┌───────────────────┐
             │ FRP Auto Deploy   │
             │ Server            │
             └─────────┬─────────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
          ▼            ▼            ▼
       Client        Client       Client
          │            │            │
      Services      Services     Services

Management
────────────────────────────────────

sudo frpctl

Clients
Services
Groups
Tags
Filters
Enrollments
Ports
Doctor
Audit
Backup
Update
```

운영자는 수십~수백 Client가 있어도:

```text
show clients
show groups
show clients --group customer-acme
show clients --tag env=prod
doctor clients --group production
```

같은 단순한 command로 관리한다.


> **2026-09-04 Scope Clarification:** 위 “수십~수백” 표현은 이전 roadmap의 장기 확장 표현이다. 현재 제품의 intended operating range는 few to a few dozen clients이며, 30~50 Clients까지 Group/Tag/Filter 정도로 편하게 관리할 수 있으면 충분하다. 수백 대 운영을 위한 fleet framework는 목표가 아니다.

---

# 70. 최종 Product Vision

FRP Auto Deploy가 궁극적으로 제공해야 하는 경험은 다음과 같다.

기존 방식:

```text
VPN
NAT
Firewall Change
Public IP
Port Forwarding
Manual FRP Config
Manual Port Tracking
Manual Client Tracking
```

FRP Auto Deploy:

```text
Install Server Once
        ↓
Generate Zero-Touch Command
        ↓
Run on Remote Client
        ↓
Automatic Secure Enrollment
        ↓
Publish Required Services
        ↓
Manage Everything with frpctl
        ↓
Group / Tag / Filter at Scale
```


### 2026-09-04 Refined Product Experience

```text
Install Server Once
        ↓
Generate a short Zero-Touch command
        ↓
Customer runs one command
        ↓
Secure enrollment
        ↓
Required SSH/HTTP/HTTPS/TCP services published
        ↓
Connect with Public IP or friendly DNS hostname
        ↓
Manage a few to a few dozen clients with frpctl
```

여기서 “at scale”은 대형 fleet orchestration이 아니라 제품의 realistic target인 몇십 대 운영을 의미한다.

제품의 핵심 가치는 기능의 숫자가 아니다.

> **방화벽 뒤 서버 연결이라는 귀찮고 반복적인 운영 작업을 안전하면서도 최대한 단순하게 만드는 것**

이다.

그리고 이 프로젝트가 앞으로 기능을 추가하면서 반드시 유지해야 할 가장 중요한 제품 원칙은:

> **Simple to deploy.  
> Simple to understand.  
> Safe to operate.  
> Lightweight by design.**

이다.

---

# 71. Master Roadmap Summary

| 영역 | 현재 상태 / 방향 |
|---|---|
| Published Stable | **v2.2.1 / FRP 0.71.0** |
| Zero-Touch Short URL Option B | **STABLE** |
| Public Hostname / DNS alias | **STABLE** |
| Simple Manual Group MVP | **STABLE** |
| Access Control Pack (Named Lists / TTL / Conn Log) | **MAIN / IN PROGRESS** (feature branch; not yet in stable) |
| Target Health Check | **PLANNED** (P1 remaining) |
| Support Bundle | **PLANNED** (P1 remaining) |
| Service Profiles | **PLANNED** (P1 remaining) |
| macOS Apple Silicon | **STABLE / Real E2E validated** |
| Windows 10 / PS5.1 Client | **STABLE / Real E2E validated** |
| Rocky 8 / Rocky 9 / AL2023 | **STABLE / Real E2E validated** |
| Amazon Linux 2 | **Portability/CI only; no live Real E2E host** |
| PowerShell 7 | **CI validated; same-host depends on `pwsh` availability** |
| Dynamic Group | OPTIONAL / LATER |
| Limited safe bulk operation | DEMAND DRIVEN |
| Controlled rollout / canary | NOT CURRENT SCOPE |
| UDP / additional protocols | DEMAND DRIVEN |
| Fleet orchestration / Web UI / DB / HA / automatic DNS/ACME | **OUT OF CURRENT SCOPE** |

---

# 71.1 Current Release Closure — v2.2.1

Current stable closure:

```text
PROJECT_VERSION=2.2.1
FRP_VERSION=0.71.0

QUALIFIED_CANDIDATE=
2140be5b6342c3651c16a458f8ea1bc9b577d992

RELEASE_COMMIT=
19d4b6fb8a9bee2d477ace6f5c3ed70310e7ea8f

CANDIDATE_RELEASE_TREE_IDENTICAL=YES

FULL_REAL_E2E_PASS_1=PASS
FULL_REAL_E2E_PASS_2=PASS
PASS_HEADS_IDENTICAL=YES

MACOS_REAL_LIBEDIT_COMPLETION=PASS
ROCKY9_REAL_E2E=PASS
AL2_PORTABILITY=PASS

PR11_MERGED=YES
TAG_V2_2_1_CREATED=YES
GITHUB_RELEASE_V2_2_1_PUBLISHED=YES
TAGGED_STABLE_PATH_SMOKE=PASS

UNRESOLVED_RELEASE_BLOCKERS=0
OWNER_MANUAL_E2E_REQUIRED=NO
```

`v2.2.0`과 `v2.2.1` published tags/releases는 immutable하게 유지한다.

Product Master 같은 docs-only closure는:

```text
NEW_RELEASE_REQUIRED=NO
NEW_TAG_REQUIRED=NO
NEW_DOUBLE_FULL_REAL_E2E_REQUIRED=NO
OWNER_MANUAL_E2E_REQUIRED=NO
```

이다.

# 71.2 Zero-Touch Short URL — Current Product Specification

Stable Linux UX:

```bash
curl -fsSL https://bootstrap.example.com/i/<ticket> | sudo bash
```

Trust model:

```text
OPTION_B_EXTERNAL_REVERSE_PROXY
```

Operator responsibilities:

- DNS
- public certificate
- reverse proxy
- `/i/` access-log suppression/redaction

Product responsibilities:

- high-entropy short-lived ticket
- hashed-at-rest
- first-machine binding at redeem
- single-use
- secure management trust
- no TLS verification weakening

Windows stable path:

```text
Short URL
→ download bootstrap file
→ SHA256 verify
→ powershell.exe -File
```

Never production `irm | iex`.

---

# 71.3 Public Hostname / DNS — Current Product Specification

```text
Public IP
= Primary infrastructure/control endpoint

Public Hostname
= Optional published-service access alias
```

Canonical admin operations:

```text
set server hostname <fqdn>
unset server hostname
```

Access examples:

```text
ssh -p 6000 admin@access.example.com
http://access.example.com:6001
https://access.example.com:6002
```

IP fallback is always preserved.

FRP Auto Deploy does not own:

```text
DNS provider records
Route53 / Cloudflare APIs
ACME / Let's Encrypt
application certificates
external firewall / NAT
```

---

# 71.4 Simple Group MVP — Current Product Scope

Required/current stable scope:

```text
create/delete/rename group
description
add/remove client membership
show groups
show group
show client <ID> groups
show clients --group
multiple membership
persistence
backup/restore
audit
Tags
basic filters
```

Not current required scope:

```text
Dynamic Group
complex AND/OR/NOT selector language
nested hierarchy
fleet-wide destructive operations
canary rollout
large-scale staged deployment
```

Group은 대형 fleet framework가 아니라 few-to-few-dozen clients를 정리하는 도구다.

---

# 72. Master Rule

새 기능 또는 코드 변경을 검토할 때 마지막으로 항상 다음 질문을 한다.

> **“이 변경이 FRP Auto Deploy를 방화벽 뒤 여러 서버를 쉽고 안전하게 연결하고 관리하는 더 좋은 lightweight 제품으로 만드는가?”**

YES라면 이 문서의 Architecture Guardrail과 Security Model을 만족하는지 확인한 뒤 개발한다.

NO라면 제품 범위에 추가하지 않는다.


추가로 항상 다음을 확인한다.

> **“이 기능이 few to a few dozen clients를 더 쉽고 안전하게 운영하게 만드는가, 아니면 제품을 불필요하게 fleet/orchestration platform으로 키우는가?”**

후자라면 실제 field demand가 확인되기 전에는 구현하지 않는다.

---

# 73. Document Provenance and Maintenance Rule

이번 canonical consolidation의 입력:

1. 개발서버 `docs/PRODUCT_MASTER.md`
   - 2,127 lines
   - SHA-256 `51e8a461b9713a390484d4b6861268061feb359918ed6ad7367512728687a848`
   - 일부 신규 상태 정보 포함
   - 다수 섹션 누락 / Markdown corruption 확인

2. `FRP Auto Deploy — Product Master Document v2026-09-04 (1)`
   - 3,728 lines
   - SHA-256 `324f74446e65da751b96e9b1ce035b9be627e35557c9aa80188ae8cd0099077e`
   - 완전한 2026-09-04 authoritative baseline

3. `01-FRP-...Product-Master-Document-v2026-09-04...`
   - 3,728 lines
   - SHA-256 `324f74446e65da751b96e9b1ce035b9be627e35557c9aa80188ae8cd0099077e`
   - 2번과 byte-identical backup copy

4. Owner-reconstructed canonical file used for the 2026-09-08 GitHub sync
   - 3,613 lines
   - 71,937 bytes
   - SHA-256 `d611d7be8e1e8649c2ab5df0818850f9e87599c1df5e68f1620ab6779051f410`
   - corruption markers absent
   - single End marker
   - used as the authoritative content base for current `v2.2.1` state updates

통합 정책:

```text
Complete 2026-09-04 baseline
+
verified post-09-04 product/release changes
-
corruption
-
stale release claims
-
duplicate historical roadmap ambiguity
=
Canonical docs/PRODUCT_MASTER.md
```

앞으로:

```text
PRODUCT_MASTER_FULL_RESTORE=PASS
AUTHORITATIVE_MASTER_AVAILABLE=YES
AUTHORITATIVE_MASTER_SOURCE=Owner-reconstructed canonical Product Master (synced to docs/PRODUCT_MASTER.md)
```

- Product Master의 별도 복사본을 새 canonical source로 만들지 않는다.
- 모든 authoritative 변경은 `docs/PRODUCT_MASTER.md`에 반영한다.
- 큰 제품 결정은 Decision Log에 추가한다.
- 현재 버전/HEAD/test state는 release마다 갱신한다.
- historical decision은 보존하되 current direction과 혼동하지 않도록 표시한다.
- 실제 code/test/release가 문서보다 항상 우선한다.

---


# 73. Access Control Pack (Named Lists / TTL / Connection Log)

**Status: MAIN / feature branch (not yet in published stable v2.2.1)**

Published service connections can be authorized with:

- **PUBLIC** — default for all existing services without access metadata
- **ALLOWLIST** — Named reusable Access List of CIDR/IP sources

Temporary Access stores absolute `expires_at` on list entries (TTL inputs like
`30m` / `4h` / `1d`). Expired entries do not match.

Connection Access Log records recent ALLOW/DENY decisions (bounded local
JSONL). Logging failures do not change authorization; ALLOWLIST policy
failures fail closed.

Enforcement uses FRP **0.71.0 NewUserConn** server HTTP plugin on loopback
(`127.0.0.1:6101`). Firewall automation is not used. Control / enrollment /
single-443 frontend paths are never filtered by Service Access Lists.

Access Control is defense-in-depth. Target authentication (SSH keys, app auth,
database auth) must remain enabled.

Remaining approved product features after this pack:

```text
P1 Target Health Check
P1 Support Bundle
P1 Service Profiles
```

---

**End of Product Master Document**