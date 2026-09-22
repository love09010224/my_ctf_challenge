# RE:CLAIM — BOX 000 풀이

## 1. 표면 분석

guest는 uid 1000 BusyBox shell과 세 device를 제공합니다.

- `/dev/reclaim`: 여러 backend에 대한 opaque token과 receipt
- `/dev/reclaim-ledger`: generation ledger, bookmark, snapshot, binary serializer
- `/dev/reclaim-codec`: 별도 renderer profile 조회

최종 flag는 일반 파일로 읽을 수 없습니다. setuid
`/usr/bin/reclaim-approval`이 매 실행마다 nonce를 내고, 내부 32-byte key로 계산한
HMAC-SHA256 응답이 맞을 때만 root-only evidence를 출력합니다. 따라서 목표는 단순
권한 상승이 아니라 archive signing key를 복구해 approval gate를 통과하는 것입니다.

## 2. 공통 last-owner race

case에 reviewer 둘을 붙인 뒤 한 thread가 publish하는 동안 다른 thread가 마지막
receipt들을 닫습니다. refcount의 마지막 owner 판단과 publish가 교차하면 archive
cursor가 해제된 뒤에도 desk 쪽 cursor 참조가 남습니다. `exploit.c`의
`begin_stale_round()`가 이 CREATE/PUBLISH/close 순서를 CPU affinity와 bounded retry로
구성합니다.

race 성공 여부는 직접 주소나 backend type으로 주어지지 않습니다. stale receipt를
정상 API로 읽고 예상 generation/locator 형태가 관찰될 때만 다음 단계로 진행합니다.

## 3. 무작위 snapshot frame 역할 찾기

ledger의 `BOOKMARK`와 `SNAPSHOT(fingerprint, revision)`은 같은 fingerprint에 대해
네 개의 216-byte frame을 만들지만 역할 순서는 매번 섞입니다. 정상 receipt view는
generation만 보이고 locator와 역할은 가립니다.

각 frame을 마지막으로 withdraw한 직후 stale cursor를 읽어 실제로 같은
`kmalloc-cg-256` slot과 겹친 frame을 찾습니다. 네 역할 중 두 개만 최종 join에
필요합니다.

1. ordering lane: tmpfs `simple_xattr` 객체로 slot을 재점유한 뒤 APPLY
2. redaction lane: queued inotify event 형태로 slot을 재점유한 뒤 RECONCILE

나머지 두 frame도 정상 audit/retention state를 변경하고 binary decoy를 만들기 때문에
단순 dead slot oracle로 분류할 수 없습니다.

## 4. 두 native consumer와 join

### Ordering lane

216-byte cursor와 동일 cache에 들어가는 xattr를 여러 개 만들고 value의 앞부분을
stale rbtree node 형태로 맞춥니다. 겹친 slot에서 APPLY가 성공하면 target anchor의
tree edge 하나가 제거됩니다. xattr header, name 길이, parent provenance가 맞지 않으면
mutation 전 거부됩니다.

### Redaction lane

다른 snapshot round에서는 inotify fixture로 redaction consumer가 요구하는 event
header와 name payload를 만듭니다. 겹친 slot에서 RECONCILE이 성공하면 target
fingerprint의 lease가 제거됩니다.

X-only는 lease 때문에, N-only는 tree reachability 때문에 serializer가 secret을
내지 않습니다. 서로 다른 fingerprint에 두 mutation을 적용해도 provenance join이
실패합니다. 같은 fingerprint의 ordering edge와 lease를 모두 제거한 경우에만 ledger
binary serializer가 bounded 32-byte candidate를 반환합니다.

## 5. approval gate와 종료

복구 후보마다 approval gate의 32-byte nonce에 HMAC-SHA256을 계산합니다. 먼저 변조한
wrong key가 거부되는지 확인한 뒤 후보를 제출합니다. 맞는 후보이면 setuid gate가
root-only evidence에서 `MAC:SHA{...}` 형식의 flag를 출력합니다.

동봉 exploit은 다음 negative oracle도 함께 확인합니다.

- 정상 snapshot decoy의 gate 거부
- uid 1000에서 evidence stream 직접 open 거부
- X-only, N-only, cross-fingerprint mismatch의 recovery 0
- wrong recovered key의 gate 거부
- 같은 fingerprint matched join과 실제 player gate 성공

## 6. archive topology 초기화 안정화

30-way 검증에서 보였던 일부 조기 종료는 exploit race나 host CPU 부족이 아니었습니다.
archive context 초기화가 무작위 RB-tree에서 candidate 네 개 이상을 요구하면서 layout을
32번만 시도했고, invariant를 만들지 못하면 `-ENOMEM`으로 종료하는 독립적인
초기화 lottery였습니다.

현재 production module은 `RECLAIM_ARCHIVE_LAYOUT_ATTEMPTS=512`로 이 초기화 상한만
늘렸습니다. 무작위 topology, 취약점과 consumer, exploit dataflow 및 사전 상한
`LANE_ATTEMPTS=96`은 그대로입니다.

현재 module과 변경되지 않은 동봉 Route 2 exploit은 development vault에서 single
1/1(최대 66.648초)을 통과한 뒤, client-level retry 없이 독립적인 cold 30-way 세
batch를 연속 30/30으로 통과했습니다. 각 batch의 가장 늦은 terminal은 168.898초,
134.125초, 158.464초였으며 모두 720초 제한 안입니다. 전체 production acceptance와
artifact hash는 [`capacity-and-acceptance.md`](../../docs/capacity-and-acceptance.md)를 참조합니다.
