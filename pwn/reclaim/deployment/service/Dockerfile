# Ubuntu 24.04 release index: sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
# Exact linux/amd64 manifest used by the validated service image:
FROM docker.io/library/ubuntu:24.04@sha256:019e8eb29a85e74d64925745884f2ec79aa27e3feab36353d24656f4d6b89467

ARG BUILD_KERNEL_SHA256=c71f589dc3e84c00006821cb60869e59c452e03300ae9dd045fd218fb525feb8
ARG BUILD_ROOTFS_SHA256=87c508c6e459102a60f6899c946c76c6209df8ace6fdefd92548788ea48dc7b3

LABEL org.opencontainers.image.title="RE:CLAIM BOX 000 standalone service" \
      org.opencontainers.image.description="One container provides one TCP-attached QEMU guest" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:24.04" \
      org.opencontainers.image.base.digest="sha256:019e8eb29a85e74d64925745884f2ec79aa27e3feab36353d24656f4d6b89467" \
      io.hspace.reclaim.kernel-sha256="${BUILD_KERNEL_SHA256}" \
      io.hspace.reclaim.rootfs-sha256="${BUILD_ROOTFS_SHA256}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends coreutils qemu-system-x86 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app \
    && chown 65534:65534 /app

COPY bzImage rootfs.cpio.gz entrypoint.sh run-qemu.sh /app/

RUN chmod 0555 /app/entrypoint.sh /app/run-qemu.sh \
    && chmod 0444 /app/bzImage /app/rootfs.cpio.gz

USER 65534:65534
EXPOSE 31337/tcp

ENTRYPOINT ["/app/entrypoint.sh"]
