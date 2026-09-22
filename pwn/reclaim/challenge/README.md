# RE:CLAIM challenge source

최종 production module, approval gate, rootfs generator와 Linux 6.12.103 build recipe입니다.
canonical prebuilt 파일은 repository Release에서 받는 것이 가장 빠릅니다.

## 요구 사항

- Linux x86-64
- GCC 13.3 / binutils 2.42 권장
- `make`, `curl`, `xz`, `cpio`, `gzip`, `qemu-system-x86_64`
- static BusyBox (`busybox-static`)
- static glibc와 OpenSSL 개발 파일

canonical kernel build metadata:

```text
Linux 6.12.103
GCC 13.3.0 (Ubuntu 24.04)
GNU ld 2.42
KBUILD_BUILD_USER=pwn3
KBUILD_BUILD_HOST=localhost
KBUILD_BUILD_VERSION=3
KBUILD_BUILD_TIMESTAMP=Thu Aug 20 01:00:56 KST 2026
```

Upstream source:

```text
https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.103.tar.xz
SHA-256 f143aaade8877ba5616e788b4482576db28481bcf557ef537f4fcc3938fc3176
```

## 빌드

```sh
make kernel
make all
make rootfs BUSYBOX=/usr/bin/busybox
make bundle
make audit
```

결과는 `build/`에 생성됩니다. 기본 rootfs에는 공개 개발 flag `SHA{test}`만 들어갑니다.
다른 flag로 재현하려면 다음처럼 별도 파일을 지정합니다.

```sh
FLAG_FILE=/secure/path/flag.txt make rootfs
```

## Artifact 차이

참가자 archive는 blind/difficulty 검증 때 고정된 module을 담고 있습니다. production
service에서는 archive topology 생성의 비본질적인 약 0.8% 초기화 실패를 없애기 위해
`RECLAIM_ARCHIVE_LAYOUT_ATTEMPTS`만 32에서 512로 높였습니다. 취약점, UAPI, 두 exploit
경로는 그대로이며 최종 공개 source는 production의 512-attempt revision입니다.

Reference hashes:

```text
c71f589dc3e84c00006821cb60869e59c452e03300ae9dd045fd218fb525feb8  bzImage
ee880e5aea018b8185fdeeed6d6338a096b16ade3656d8bb3b867158d0dcc9c4  linux-6.12.103.config
cb1535aa0d7c24a6239ca03502addd5786f0ffa8c023f8e9b1a580e14dacd02f  module source
2f307b13857cbab9fd7ef9ac62ac7cffc3d05ae82c264cb0ece099496c534008  module, unstripped
d3448db0fed9ae561fcba3e9e69fa7ee45b8d3fa67e4bc2af51062b8c75d3f76  module, production stripped
```
