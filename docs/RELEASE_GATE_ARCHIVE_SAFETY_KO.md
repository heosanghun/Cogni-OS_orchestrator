# Release Gate 아카이브 경로 안전성

## 보안 경계

`release.gate issue`는 `archive/release-gates/<commit>/<sha256>/`의 부모
경로를 문자열로 검사한 뒤 파일을 여는 방식을 사용하지 않는다. 그런 방식은 검사와
열기 사이에 부모 디렉터리가 심볼릭 링크나 reparse point로 교체되는 TOCTOU 공격을
막을 수 없기 때문이다.

지원되는 POSIX 환경에서는 다음 조건을 모두 만족해야 한다.

- 파일시스템 루트부터 워크스페이스와 아카이브 목적지까지 각 디렉터리를
  `O_DIRECTORY | O_NOFOLLOW`로 연다.
- 다음 구성요소의 생성과 열기는 항상 직전 부모 디렉터리 descriptor에 상대적인
  `mkdirat/openat` 동작으로 수행한다.
- 최종 `release-gate.json`은 열린 목적지 descriptor에 상대적으로
  `O_CREAT | O_EXCL | O_NOFOLLOW`로 생성한다.
- 쓰기 전후 regular-file 상태와 내용 SHA-256을 확인하고 파일과 디렉터리를
  `fsync`한다.
- 검증 때에도 동일한 descriptor chain으로 계약을 읽는다.

부모 경로가 생성 직후 링크로 교체되어도 다음 열기는 이미 보유한 부모 descriptor를
기준으로 수행되며, `O_NOFOLLOW`가 교체된 링크를 거부한다. 공격자가 가리킨 외부
디렉터리에는 계약 바이트를 쓰지 않는다.

## Windows 제한과 fail-closed 정책

현재 CPython Windows 런타임은 `os.open(..., dir_fd=...)`, `O_DIRECTORY`,
`O_NOFOLLOW`에 해당하는 안전한 부모-handle 상대 파일 생성을 제공하지 않는다.
따라서 Windows에서 release gate 발행과 검증은 `NO_GO`이며, 발행은 actor capability
소비, 원장 추가, `archive/release-gates` 생성보다 먼저 종료한다. 경로 검사 후
`CreateFileW`를 전체 경로로 호출하는 우회는 부모 교체 경쟁을 남기므로 사용하지
않는다.

Windows 지원은 Phase 2에서 별도 고권한 브로커가 Win32/NT의 부모 디렉터리 handle
상대 생성(`NtCreateFile` 계열)을 캡슐화하고, reparse point와 파일 ID를 검증하며,
독립 보안 테스트를 통과한 뒤에만 활성화할 수 있다. 그 전까지 Windows release gate
상태를 PASS로 표시해서는 안 된다.

## 검증 범위

- 미지원 플랫폼에서 capability/ledger/archive 불변성
- 기존 release-gates 경로가 링크인 경우 외부 쓰기 차단
- 디렉터리 생성 직후 부모를 링크로 교체하는 결정적 공격 재현
- content-addressed 계약의 exclusive 생성, bounded read, inventory 및 hash 확인

동일 OS 사용자나 관리자 권한 공격자로부터 전체 워크스페이스를 보호한다는 주장은
하지 않는다. actor OS 격리와 파일시스템 ACL은 별도의 release gate 선행 조건이다.
