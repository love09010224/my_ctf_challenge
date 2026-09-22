/* SPDX-License-Identifier: MIT */
#ifndef RECLAIM_V4_KEY_STATIC_6_12_103_H
#define RECLAIM_V4_KEY_STATIC_6_12_103_H

/*
 * Organizer-side constants recovered from the exact 6.12.103 vmlinux whose
 * bzImage SHA-256 is
 * c71f589dc3e84c00006821cb60869e59c452e03300ae9dd045fd218fb525feb8.
 *
 * This header is deliberately not a player ABI.  The public path must derive
 * the symbol deltas from the supplied kernel and the structure offsets from
 * static analysis; no runtime layout ioctl supplies them.
 */
#define V4S_NOOP_LLSEEK_DELTA             UINT64_C(0)
#define V4S_COMMIT_CREDS_DELTA            (-INT64_C(0x1f3d70))
#define V4S_INIT_TASK_DELTA               INT64_C(0x1350cb0)
#define V4S_INIT_CRED_DELTA               INT64_C(0x1397690)
#define V4S_KEY_TYPE_USER_DELTA           INT64_C(0x150ad30)
#define V4S_KEY_TYPE_BIG_KEY_DELTA        INT64_C(0x150af10)
#define V4S_VMEMMAP_BASE_DELTA            INT64_C(0x11f4558)
#define V4S_PAGE_OFFSET_BASE_DELTA        INT64_C(0x11f4568)

#define V4S_KEY_SIZE                      0xd8U
#define V4S_KEY_TYPE_SIZE                 0xa8U
#define V4S_KEY_TYPE_OFFSET               0x98U
#define V4S_KEY_PAYLOAD_OFFSET            0xb0U
#define V4S_KEY_TYPE_REVOKE_OFFSET        0x50U
#define V4S_KEY_TYPE_READ_OFFSET          0x68U

#define V4S_CRED_SIZE                     0xb8U
#define V4S_CRED_USAGE_OFFSET             0x00U
#define V4S_CRED_UID_OFFSET               0x08U
#define V4S_CRED_GID_OFFSET               0x0cU
#define V4S_CRED_SUID_OFFSET              0x10U
#define V4S_CRED_SGID_OFFSET              0x14U
#define V4S_CRED_EUID_OFFSET              0x18U
#define V4S_CRED_EGID_OFFSET              0x1cU
#define V4S_CRED_FSUID_OFFSET             0x20U
#define V4S_CRED_FSGID_OFFSET             0x24U
#define V4S_CRED_SECUREBITS_OFFSET        0x28U
#define V4S_CRED_CAP_INHERITABLE_OFFSET   0x30U
#define V4S_CRED_CAP_PERMITTED_OFFSET     0x38U
#define V4S_CRED_CAP_EFFECTIVE_OFFSET     0x40U
#define V4S_CRED_CAP_BSET_OFFSET          0x48U
#define V4S_CRED_CAP_AMBIENT_OFFSET       0x50U
#define V4S_CRED_SECURITY_OFFSET          0x80U
#define V4S_CRED_USER_OFFSET              0x88U
#define V4S_CRED_USER_NS_OFFSET           0x90U
#define V4S_CRED_UCOUNTS_OFFSET           0x98U
#define V4S_CRED_GROUP_INFO_OFFSET        0xa0U

#define V4S_TASK_SIZE                     0x1cc0U
#define V4S_TASK_TASKS_OFFSET             0x4b0U
#define V4S_TASK_PID_OFFSET               0x580U
#define V4S_TASK_TGID_OFFSET              0x584U
#define V4S_TASK_REAL_CRED_OFFSET         0x750U
#define V4S_TASK_CRED_OFFSET              0x758U
#define V4S_TASK_COMM_OFFSET              0x768U
#define V4S_TASK_FILES_OFFSET             0x7a0U
#define V4S_FILES_FDT_OFFSET              0x20U
#define V4S_FDTABLE_FD_OFFSET             0x08U
#define V4S_FILE_PRIVATE_DATA_OFFSET       0x20U
#define V4S_CTX_WORKPADS_OFFSET           0x28a8U
#define V4S_STRUCT_PAGE_SIZE              0x40U

#endif
