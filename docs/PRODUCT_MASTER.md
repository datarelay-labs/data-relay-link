# FRP Auto Deploy — Product Master Document

> **Document role:** Product Charter + Product Specification + Architecture Principles + Roadmap
> **Repository:** `datarelay-labs/frp-auto-deploy`
> **Document status:** Master / Living Document
> **Last updated:** 2026-09-08
> **Current stable baseline:** Project 2.2.0 published; **2.2.1** stable identity (this line)
> **Development line:** 2.2.1 hardening (libedit, FRP gate, metadata, docs) on release candidate
> **Release HEAD (published stable):** `04a2474c6f3b83f444341752bfd6c4a500480556`
> **Pinned upstream FRP:** 0.71.0 (exact pin; not follow-latest)
> **Primary management interface:** `sudo frpctl`
> **ZERO_TOUCH_SHORT_URL_TRUST_MODEL:** OPTION_B_EXTERNAL_REVERSE_PROXY (stable in v2.2.0)

### Current validated platforms (v2.2.0)

| Platform | Validation level |
|----------|------------------|
| Ubuntu 24 physical | Real E2E validated |
| Rocky Linux 8.10 | Real E2E validated |
| Rocky Linux 9.4 | Real E2E validated |
| Amazon Linux 2023 | Real E2E validated |
| Amazon Linux 2 | Container / CI portability (no live host in v2.2.0 gate) |
| macOS Apple Silicon | Real E2E validated |
| Windows 10 PS5.1 | Real E2E validated |
| Windows PowerShell 7 | Automated CI validated; same real host SKIPPED when `pwsh` absent |

Windows Zero-Touch remains: download → SHA256 verify → `powershell.exe -File`. Never `irm \| iex`.


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
- 향후 Group 기반 대규모 운영

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
                │ (+ optional    │
                │  DNS hostname) │
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

대표적인 Client 설치 경험:

```text
curl ... | sudo bash
```

또는 Zero-touch 명령 한 줄을 원격 사용자에게 전달한다.

운영자는 이후 대부분의 작업을:

```text
sudo frpctl
```

에서 수행한다.

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

현재 기준:

```text
FRP 0.71.0
```

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

```textuct Direction

Client 수가 증가하면 단순 `show clients`만으로 운영하기 어려워진다.

따라서 Grouping 기능을 핵심 확장 기능으로 도입한다.

그러나 Group만으로 모든 분류를 해결하지 않는다.

최종 모델:

```text
Group
+
Tag
+
Selector
+
Filter
```

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

세 가지 Group type을 정의한다.

## Manual Group

관리자가 직접 membership을 관리한다.

예:

```text
pilot
customer-acme
migration-wave-1
```

---

## Dynamic Group

Tag selector 조건에 의해 자동 계산한다.

예:

```text
prod-seoul

env=prod
AND
site=seoul
```

기존 tag matching 기능을 활용한다.

첫 구현에서는 단순 AND 조건을 지원한다.

---

## System Group

시스템이 제공한다.

최소:

```text
all
ungrouped
```

### all

모든 Client.

### ungrouped

사용자가 정의한 manual grouping 관점에서 아직 분류되지 않은 Client를 찾기 위한 operational view.

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

예:

```text
create group prod-seoul \
  --dynamic \
  --match-tag env=prod \
  --match-tag site=seoul
```

의미:

```text
env=prod
AND
site=seoul
```

Dynamic membership을 Client record에 중복 저장하지 않는다.

Tag가 source of truth이며 membership은 selector 결과로 계산한다.

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

Client 설치 시 Group을 미리 지정할 수 있어야 한다.

예:

```text
create zero-touch --group customer-acme
```

또는:

```text
create enrollment --group customer-acme
```

Enrollment 완료 후 Server가 membership을 적용한다.

Client가 Group을 self-assign할 수 없어야 한다.

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

Group의 진짜 가치는 대규모 operation에서 발생한다.

장기 목표:

```text
doctor clients --group customer-acme

update clients --group pilot

show services --group production
```

그러나 destructive bulk operation은 매우 보수적으로 설계한다.

특히:

```text
revoke group
release group
```

같은 명령은 초기 Group implementation 범위에 포함하지 않는다.

Bulk mutation에는 최소:

```text
Target
Matched clients
Expected operation
Preview
Confirmation
Per-client result
Audit record
```

가 필요하다.

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

같은 Project Version이라도 다른 build일 수 있다.

따라서:

```text
PROJECT_VERSION
```

만으로 update 필요 여부를 결정해서는 안 된다.

가능한 경우:

```text
release channel
source ref
verified SHA256
bundle identity
```

를 사용한다.

Unknown build identity는:

```text
"already up to date"
```

로 판정하지 않는다.

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
- Linux Client

### Connectivity

- TCP
- SSH
- HTTP
- HTTPS passthrough
- Custom TCP
- LAN target publishing

### Management

- Enrollment
- Zero-touch
- Persistent client identity
- Multi-service
- Persistent public port
- Client metadata
- Tags
- CLI
- Doctor
- Audit
- Backup / Restore
- Update
- Release / Revoke

### Deployment

- Direct
- Enterprise single-443
- Public/listen port split

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

Prometheus/Grafana/RMM 형태의 motion

을 우회하지 않는다.

---

# 50. Current Product Status

## Stable Baseline

현재 repository 기준:

```text
Published stable:       2.2.0 (tag v2.2.0)
Development candidate: integration/morning-e2e-ready
Candidate-only scope:   macOS / Windows / Group MVP (human Real E2E pending)
FRP:                    0.71.0
Published Release HEAD: 97cb84ebb0b09d771c623778b1a551edd6fc9204
ZERO_TOUCH_SHORT_URL_TRUST_MODEL: OPTION_B_EXTERNAL_REVERSE_PROXY
```

v2.2.0 stable focus:

- Ideal Zero-Touch `/i/<ticket>` short URL (Option B)
- optional `bootstrap_hostname` + operator reverse proxy
- transitional `zt1.` package remains the default fallback
- FRP remains 0.71.0

Ideal `/i/<ticket>` short URL is implemented as an additive Option B feature
(operator reverse proxy + `bootstrap_hostname`). See
`docs/ZERO_TOUCH_SHORT_URL.md`. Missing `bootstrap_hostname` keeps the `zt1`
fallback.

The integration candidate additionally contains:

- macOS Apple Silicon launchd client
- Windows amd64 PowerShell client
- Manual Group MVP

These three additions are **candidate / human-Real-E2E pending**, not stable
platform or feature claims.

Target management scale:

- 1–5 clients: extremely easy
- 10–30 clients: comfortable
- 30–50 clients: manageable with simple Group/Tag/Filter
- Product target: 1–50 clients
- 100+: not a product target

2.1.1의 주요 stable milestone:

- Secure HTTPS Enrollment
- Project private CA
- Persistent ECDSA management identity
- Zero-touch bootstrap
- Multi-service TCP Client
- Persistent public ports
- Direct mode
- Enterprise single-443
- Backup / restore
- Doctor
- Update safety
- Lifecycle semantics
- Linux distribution compatibility work

---

# 51. Main / Development State

Stable release와 `main` development state를 구분한다.

현재 `main`에는 2.1.0 이후 다음 계열 개선이 진행되어 왔다.

- canonical `frpctl` verb/resource grammar
- CLIENT ID 중심 selector
- context help
- Tab completion
- in-memory history
- shell-safe parsing
- unified enrollment listing
- same-version build identity verification
- update hardening
- release metadata hardening
- Zero-touch guided UX 개선

따라서:

```text
Stable Release
!=
Current Main HEAD
```

일 수 있다.

Master Document에서 기능 상태를 표시할 때 반드시 이를 구분한다.

---

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

**Status: STABLE / MAIN**

목표:

> 일상 운영을 `frpctl` 하나로 통합한다.

포함:

- SSH
- HTTP
- HTTPS
- Custom TCP
- multiple services
- LAN target
- persistent ports
- add/edit/disable/enable
- release/revoke distinction
- client label/note/tags
- CLIENT ID selector
- CLI grammar
- Tab
- contextual help
- shell-safe parser
- Zero-touch UX 개선

남은 작업은 Stable/Main 상태를 릴리즈 시점마다 재분류한다.

---

# 56. Phase 3 — Group & Fleet Management

**Status: CANDIDATE — MANUAL GROUP MVP HUMAN REAL E2E PENDING**

목표:

> Client 수가 늘어나도 CLI만으로 효율적으로 관리할 수 있게 한다.

### P3.1 Manual Group

- immutable Group ID
- Group name
- description
- multiple membership
- `show groups`
- `show group`
- `show clients --group`
- `show client <ID> groups`
- add/remove membership
- audit
- backup/restore
- re-enrollment preservation

### P3.2 Enrollment Group Assignment

```text
create zero-touch --group ...
create enrollment --group ...
```

### P3.3 System Groups

```text
all
ungrouped
```

### P3.4 Dynamic Groups

기존 Tags 이용.

```text
customer=acme
site=seoul
env=prod
```

Selector MVP:

```text
AND
`lled Rollout

**Status: FUTURE**

Group을 활용한 rollout.

예:

```text
pilot
production
```

흐름:

```text
New Project/FRP Version
        ↓
Pilot Group
        ↓
Validation
        ↓
Production Group
```

장기적으로 다음을 검토할 수 있다.

- staged update
- canary
- maintenance group
- failed update retry
- rollout summary

단, 별도 대형 orchestration system으로 발전시키지 않는다.

---

# 59. Phase 6 — Additional Platform Support

**Status: macOS/WINDOWS CANDIDATE — HUMAN REAL E2E PENDING**

Integration candidate validation scope:

### Windows Client

- PowerShell bootstrap
- persistent identity
- `frpc.exe`
- RDP preset
- SSH
- HTTP/HTTPS
- Custom TCP
- LAN gateway
- Windows Service integration

### ARM64

실환경 validation 이후 공식 지원 확대.

### Additional Linux

실제 VM과 security mode를 기준으로 지원 범위를 확장.

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
CLI
↓
Lifecycle
↓
Upgrade
↓
Distribution Matrix
↓
Real Environment
```

Group 기능의 최소 test matrix:

### Group CRUD

- create
- rename
- description
- remove

### Membership

- add
- remove
- duplicate
- nonexistent Client
- nonexistent Group
- multiple Groups

### Dynamic Groups

- exact tag match
- multiple AND tags
- tag change
- tag removal

### Persistence

- server reboot
- project update
- backup
- restore
- re-enrollment

### CLI

- Tab
- help
- ambiguous Client
- ambiguous Group
- quoted description
- malicious shell-like input

### Security

- Client cannot self-assign Group
- malformed Group ID
- registry corruption
- audit

---

# 64. Documentation Structure

권장 문서 구조:

```text
README.md
    │
    ├── Quick Start
    └── Product Overview

docs/
├âFirst

**Decision**

Web UI/DB보다 `sudo frpctl`을 제품의 중심 interface로 유지한다.

**Reason**

제품의 핵심 가치가 lightweight remote access management이기 때문이다.

---

## 2026-08 — CLIENT ID First

**Decision**

hostname/IP 대신 immutable CLIENT ID를 canonical selector로 사용한다.

**Reason**

hostname/IP/label 변경과 무관한 안정적인 identity가 필요하다.

---

## 2026-08 — Zero-Touch + Manual Enrollment

**Decision**

Zero-touch를 기본 UX로 제공하되 Manual Enrollment를 제거하지 않는다.

---

## 2026-08 — Multi-Service Client

**Decision**

한 Client는 하나의 SSH endpoint가 아니라 여러 TCP service를 제공할 수 있다.

---

## 2026-08 — LAN Gateway

**Decision**

Client 자신의 localhost뿐 아니라 Client가 접근 가능한 LAN target도 Service로 publish할 수 있다.

---

## 2026-08 — Enterprise single-443

**Decision**

기업 firewall 환경을 위해 Enrollment HTTPS와 FRP WSS control을 TCP/443에서 제공하는 mode를 지원한다.

---

## 2026-08 — Group + Tag

**Decision**

대규모 Client 관리를 위해 단순 단일 Group 필드가 아니라:

```text
Manual Group
+
Dynamic Group
+
Existing Tags
+
Filters
```

모델을 사용한다.

**Reason**

고객, 위치, 환경, 역할 등 여러 관리 축을 동시에 표현해야 하기 때문이다.

---

## 2026-08 — No Group Hierarchy Initially

**Decision**

Parent/Child Group은 첫 Group release에서 구현하지 않는다.

**Reason**

Tag selector로 대부분의 hierarchy 요구를 해결할 수 있으며 초기 복잡도를 크게 줄일 수 있다.

---

## 2026-08 — Safe Fleet Operations

**Decision**

Group 단위 destructive bulk operation은 Group MVP에 포함하지 않는다.

**Reason**

잘못된 명령 하나가 여러 Client의 identity 또는 port를 제거할 위험이 있기 때문이다.

---

# 68. Near-Term Development Priority

현재 제품 관점에서 가장 높은 우선순위는 다음이다.

```text
1. Close v2.1.3 candidate (Zero-Touch short URL) then final release gate
2. Group Management MVP
3. Dynamic Group / Filters
4. Safe Group Operations
5. 실제 사용 요구 기반 추가 플랫폼
```

Zero-Touch short-command note:

- Ideal `curl https://<bootstrap-host>/i/<ticket> | sudo bash` is implemented via
  Option B (operator reverse proxy + optional `bootstrap_hostname`).
- `ZERO_TOUCH_SHORT_URL_TRUST_MODEL=OPTION_B_EXTERNAL_REVERSE_PROXY`
- Current transitional short form (`zt1.`) remains the default when
  `bootstrap_hostname` is unset.
- Legacy long `env FRP_*=...` Zero-Touch commands remain supported.

즉 현 시점에서 Group MVP는 v2.1.3 candidate closure 이후에 착수한다.

---

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

같은 LE / MAIN |
| Phase 3 | Manual Group MVP | **SHIPPED in v2.2.0** (Real E2E validated) |
| Phase 3+ | Dynamic Group & Filters | OPTIONAL / LATER (demand-driven) |
| Phase 4 | Safe Fleet Operations | DEPRIORITIZED (not in lightweight 1–50 scope) |
| Phase 5 | Pilot/Production Rollout | FUTURE / DEMAND DRIVEN |
| Phase 6 | macOS/Windows | **SHIPPED in v2.2.0** (see platform matrix above) |
| Phase 6+ | Additional Platforms | DEFERRED / DEMAND DRIVEN |
| Phase 7 | UDP/Additional Protocols | DEFERRED |

---

## 2026-09-08 Decision — Post-v2.2.0 hardening + Product Master currency

v2.2.0 shipped with pinned FRP **0.71.0** after Double Full Real E2E on the
integration candidate. Post-release hardening addresses libedit Tab completion,
fail-closed FRP compatibility gating, public operational-metadata scrubbing in
docs, and documentation version drift.

**Authoritative Product Master attachment:** not available in this agent
session (`BLOCKED_MISSING_AUTHORITATIVE_MASTER` for full historical restore).
This living tree was updated for current release/platform truth only; product
philosophy remains Lightweight / CLI / Zero-Touch / Official pinned FRP /
Fail Closed / 1–50 clients. No Web UI, DB, fleet orchestration, or automatic
DNS/ACME was added.

**Current direction (authoritative over older roadmap prose):**

- Manual Group MVP: shipped
- Dynamic Group / Safe Fleet Operations / Controlled Rollout: optional or
  deprioritized; not required for the 1–50 client product
- FRP remains exact-pinned; future bumps need explicit qualification

---

# 72. Master Rule

새 기능 또는 코드 변경을 검토할 때 마지막으로 항상 다음 질문을 한다.

> **“이 변경이 FRP Auto Deploy를 방화벽 뒤 여러 서버를 쉽고 안전하게 연결하고 관리하는 더 좋은 lightweight 제품으로 만드는가?”**

YES라면 이 문서의 Architecture Guardrail과 Security Model을 만족하는지 확인한 뒤 개발한다.

NO라면 제품 범위에 추가하지 않는다.

---

**End of Product Master Document**


## 2026-09-08 Decision — 2.2.1 follow-up release (do not retag v2.2.0)

Addendum hardening landed after `v2.2.0` was already published. Product Master
full authoritative restore remains **BLOCKED_MISSING_AUTHORITATIVE_MASTER**
without Owner attachment. Currency/platform matrix was updated in-tree.
Follow-up release is **v2.2.1** (FRP remains exact pin **0.71.0**).
