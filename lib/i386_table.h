/* i386_table.h --
 * Copyright 2005-24 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

_S(0, "restart_syscall")
_S(1, "exit")
_S(2, "fork")
_S(3, "read")
_S(4, "write")
_S(5, "open")
_S(6, "close")
_S(7, "waitpid")
_S(8, "creat")
_S(9, "link")
_S(10, "unlink")
_S(11, "execve")
_S(12, "chdir")
_S(13, "time")
_S(14, "mknod")
_S(15, "chmod")
_S(16, "lchown")
_S(17, "break")
_S(18, "oldstat")
_S(19, "lseek")
_S(20, "getpid")
_S(21, "mount")
_S(22, "umount")
_S(23, "setuid")
_S(24, "getuid")
_S(25, "stime")
_S(26, "ptrace")
_S(27, "alarm")
_S(28, "oldfstat")
_S(29, "pause")
_S(30, "utime")
_S(31, "stty")
_S(32, "gtty")
_S(33, "access")
_S(34, "nice")
_S(35, "ftime")
_S(36, "sync")
_S(37, "kill")
_S(38, "rename")
_S(39, "mkdir")
_S(40, "rmdir")
_S(41, "dup")
_S(42, "pipe")
_S(43, "times")
_S(44, "prof")
_S(45, "brk")
_S(46, "setgid")
_S(47, "getgid")
_S(48, "signal")
_S(49, "geteuid")
_S(50, "getegid")
_S(51, "acct")
_S(52, "umount2")
_S(53, "lock")
_S(54, "ioctl")
_S(55, "fcntl")
_S(56, "mpx")
_S(57, "setpgid")
_S(58, "ulimit")
_S(59, "oldolduname")
_S(60, "umask")
_S(61, "chroot")
_S(62, "ustat")
_S(63, "dup2")
_S(64, "getppid")
_S(65, "getpgrp")
_S(66, "setsid")
_S(67, "sigaction")
_S(68, "sgetmask")
_S(69, "ssetmask")
_S(70, "setreuid")
_S(71, "setregid")
_S(72, "sigsuspend")
_S(73, "sigpending")
_S(74, "sethostname")
_S(75, "setrlimit")
_S(76, "getrlimit")
_S(77, "getrusage")
_S(78, "gettimeofday")
_S(79, "settimeofday")
_S(80, "getgroups")
_S(81, "setgroups")
_S(82, "select")
_S(83, "symlink")
_S(84, "oldlstat")
_S(85, "readlink")
_S(86, "uselib")
_S(87, "swapon")
_S(88, "reboot")
_S(89, "readdir")
_S(90, "mmap")
_S(91, "munmap")
_S(92, "truncate")
_S(93, "ftruncate")
_S(94, "fchmod")
_S(95, "fchown")
_S(96, "getpriority")
_S(97, "setpriority")
_S(98, "profil")
_S(99, "statfs")
_S(100, "fstatfs")
_S(101, "ioperm")
_S(102, "socketcall")
_S(103, "syslog")
_S(104, "setitimer")
_S(105, "getitimer")
_S(106, "stat")
_S(107, "lstat")
_S(108, "fstat")
_S(109, "olduname")
_S(110, "iopl")
_S(111, "vhangup")
_S(112, "idle")
_S(113, "vm86old")
_S(114, "wait4")
_S(115, "swapoff")
_S(116, "sysinfo")
_S(117, "ipc")
_S(118, "fsync")
_S(119, "sigreturn")
_S(120, "clone")
_S(121, "setdomainname")
_S(122, "uname")
_S(123, "modify_ldt")
_S(124, "adjtimex")
_S(125, "mprotect")
_S(126, "sigprocmask")
_S(127, "create_module")
_S(128, "init_module")
_S(129, "delete_module")
_S(130, "get_kernel_syms")
_S(131, "quotactl")
_S(132, "getpgid")
_S(133, "fchdir")
_S(134, "bdflush")
_S(135, "sysfs")
_S(136, "personality")
_S(137, "afs_syscall")
_S(138, "setfsuid")
_S(139, "setfsgid")
_S(140, "_llseek")
_S(141, "getdents")
_S(142, "_newselect")
_S(143, "flock")
_S(144, "msync")
_S(145, "readv")
_S(146, "writev")
_S(147, "getsid")
_S(148, "fdatasync")
_S(149, "_sysctl")
_S(150, "mlock")
_S(151, "munlock")
_S(152, "mlockall")
_S(153, "munlockall")
_S(154, "sched_setparam")
_S(155, "sched_getparam")
_S(156, "sched_setscheduler")
_S(157, "sched_getscheduler")
_S(158, "sched_yield")
_S(159, "sched_get_priority_max")
_S(160, "sched_get_priority_min")
_S(161, "sched_rr_get_interval")
_S(162, "nanosleep")
_S(163, "mremap")
_S(164, "setresuid")
_S(165, "getresuid")
_S(166, "vm86")
_S(167, "query_module")
_S(168, "poll")
_S(169, "nfsservctl")
_S(170, "setresgid")
_S(171, "getresgid")
_S(172, "prctl")
_S(173, "rt_sigreturn")
_S(174, "rt_sigaction")
_S(175, "rt_sigprocmask")
_S(176, "rt_sigpending")
_S(177, "rt_sigtimedwait")
_S(178, "rt_sigqueueinfo")
_S(179, "rt_sigsuspend")
_S(180, "pread64")
_S(181, "pwrite64")
_S(182, "chown")
_S(183, "getcwd")
_S(184, "capget")
_S(185, "capset")
_S(186, "sigaltstack")
_S(187, "sendfile")
_S(188, "getpmsg")
_S(189, "putpmsg")
_S(190, "vfork")
_S(191, "ugetrlimit")
_S(192, "mmap2")
_S(193, "truncate64")
_S(194, "ftruncate64")
_S(195, "stat64")
_S(196, "lstat64")
_S(197, "fstat64")
_S(198, "lchown32")
_S(199, "getuid32")
_S(200, "getgid32")
_S(201, "geteuid32")
_S(202, "getegid32")
_S(203, "setreuid32")
_S(204, "setregid32")
_S(205, "getgroups32")
_S(206, "setgroups32")
_S(207, "fchown32")
_S(208, "setresuid32")
_S(209, "getresuid32")
_S(210, "setresgid32")
_S(211, "getresgid32")
_S(212, "chown32")
_S(213, "setuid32")
_S(214, "setgid32")
_S(215, "setfsuid32")
_S(216, "setfsgid32")
_S(217, "pivot_root")
_S(218, "mincore")
_S(219, "madvise")
_S(219, "madvise1")
_S(220, "getdents64")
_S(221, "fcntl64")
_S(224, "gettid")
_S(225, "readahead")
_S(226, "setxattr")
_S(227, "lsetxattr")
_S(228, "fsetxattr")
_S(229, "getxattr")
_S(230, "lgetxattr")
_S(231, "fgetxattr")
_S(232, "listxattr")
_S(233, "llistxattr")
_S(234, "flistxattr")
_S(235, "removexattr")
_S(236, "lremovexattr")
_S(237, "fremovexattr")
_S(238, "tkill")
_S(239, "sendfile64")
_S(240, "futex")
_S(241, "sched_setaffinity")
_S(242, "sched_getaffinity")
_S(243, "set_thread_area")
_S(244, "get_thread_area")
_S(245, "io_setup")
_S(246, "io_destroy")
_S(247, "io_getevents")
_S(248, "io_submit")
_S(249, "io_cancel")
_S(250, "fadvise64")
_S(252, "exit_group")
_S(253, "lookup_dcookie")
_S(254, "epoll_create")
_S(255, "epoll_ctl")
_S(256, "epoll_wait")
_S(257, "remap_file_pages")
_S(258, "set_tid_address")
_S(259, "timer_create")
_S(260, "timer_settime")
_S(261, "timer_gettime")
_S(262, "timer_getoverrun")
_S(263, "timer_delete")
_S(264, "clock_settime")
_S(265, "clock_gettime")
_S(266, "clock_getres")
_S(267, "clock_nanosleep")
_S(268, "statfs64")
_S(269, "fstatfs64")
_S(270, "tgkill")
_S(271, "utimes")
_S(272, "fadvise64_64")
_S(273, "vserver")
_S(274, "mbind")
_S(275, "get_mempolicy")
_S(276, "set_mempolicy")
_S(277, "mq_open")
_S(278, "mq_unlink")
_S(279, "mq_timedsend")
_S(280, "mq_timedreceive")
_S(281, "mq_notify")
_S(282, "mq_getsetattr")
_S(283, "sys_kexec_load")
_S(284, "waitid")
// 285  is setaltroot but it is not defined (yet)
_S(286, "add_key")
_S(287, "request_key")
_S(288, "keyctl")
_S(289, "ioprio_set")
_S(290, "ioprio_get")
_S(291, "inotify_init")
_S(292, "inotify_add_watch")
_S(293, "inotify_rm_watch")
_S(294, "migrate_pages")
_S(295, "openat")
_S(296, "mkdirat")
_S(297, "mknodat")
_S(298, "fchownat")
_S(299, "futimesat")
_S(300, "fstatat64")
_S(301, "unlinkat")
_S(302, "renameat")
_S(303, "linkat")
_S(304, "symlinkat")
_S(305, "readlinkat")
_S(306, "fchmodat")
_S(307, "faccessat")
_S(308, "pselect6")
_S(309, "ppoll")
_S(310, "unshare")
_S(311, "set_robust_list")
_S(312, "get_robust_list")
_S(313, "splice")
_S(314, "sync_file_range")
_S(315, "tee")
_S(316, "vmsplice")
_S(317, "move_pages")
_S(318, "getcpu")
_S(319, "epoll_pwait")
_S(320, "utimensat")
_S(321, "signalfd")
_S(322, "timerfd_create")
_S(323, "eventfd")
_S(324, "fallocate")
_S(325, "timerfd_settime")
_S(326, "timerfd_gettime")
_S(327, "signalfd4")
_S(328, "eventfd2")
_S(329, "epoll_create1")
_S(330, "dup3")
_S(331, "pipe2")
_S(332, "inotify_init1")
_S(333, "preadv")
_S(334, "pwritev")
_S(335, "rt_tgsigqueueinfo")
_S(336, "perf_event_open")
_S(337, "recvmmsg")
_S(338, "fanotify_init")
_S(339, "fanotify_mark")
_S(340, "prlimit64")
_S(341, "name_to_handle_at")
_S(342, "open_by_handle_at")
_S(343, "clock_adjtime")
_S(344, "syncfs")
_S(345, "sendmmsg")
_S(346, "setns")
_S(347, "process_vm_readv")
_S(348, "process_vm_writev")
_S(349, "kcmp")
_S(350, "finit_module")
_S(351, "sched_setattr")
_S(352, "sched_getattr")
_S(353, "renameat2")
_S(354, "seccomp")
_S(355, "getrandom")
_S(356, "memfd_create")
_S(357, "bpf")
_S(358, "execveat")
_S(359, "socket")
_S(360, "socketpair")
_S(361, "bind")
_S(362, "connect")
_S(363, "listen")
_S(364, "accept4")
_S(365, "getsockopt")
_S(366, "setsockopt")
_S(367, "getsockname")
_S(368, "getpeername")
_S(369, "sendto")
_S(370, "sendmsg")
_S(371, "recvfrom")
_S(372, "recvmsg")
_S(373, "shutdown")
_S(374, "userfaultfd")
_S(375, "membarrier")
_S(376, "mlock2")
_S(377, "copy_file_range")
_S(378, "preadv2")
_S(379, "pwritev2")
_S(380, "pkey_mprotect")
_S(381, "pkey_alloc")
_S(382, "pkey_free")
_S(383, "statx")
_S(384, "arch_prctl")
_S(385, "io_pgetevents")
_S(386, "rseq")
_S(393, "semget")
_S(394, "semctl")
_S(395, "shmget")
_S(396, "shmctl")
_S(397, "shmat")
_S(398, "shmdt")
_S(399, "msgget")
_S(400, "msgsnd")
_S(401, "msgrcv")
_S(402, "msgctl")
_S(403, "clock_gettime64")
_S(404, "clock_settime64")
_S(405, "clock_adjtime64")
_S(406, "clock_getres_time64")
_S(407, "clock_nanosleep_time64")
_S(408, "timer_gettime64")
_S(409, "timer_settime64")
_S(410, "timerfd_gettime64")
_S(411, "timerfd_settime64")
_S(412, "utimensat_time64")
_S(413, "pselect6_time64")
_S(414, "ppoll_time64")
_S(416, "io_pgetevents_time64")
_S(417, "recvmmsg_time64")
_S(418, "mq_timedsend_time64")
_S(419, "mq_timedreceive_time64")
_S(420, "semtimedop_time64")
_S(421, "rt_sigtimedwait_time64")
_S(422, "futex_time64")
_S(423, "sched_rr_get_interval64")
_S(424, "pidfd_send_signal")
_S(425, "io_uring_setup")
_S(426, "io_uring_enter")
_S(427, "io_uring_register")
_S(428, "open_tree")
_S(429, "move_mount")
_S(430, "fsopen")
_S(431, "fsconfig")
_S(432, "fsmount")
_S(433, "fspick")
_S(434, "pidfd_open")
_S(435, "clone3")
_S(436, "close_range")
_S(437, "openat2")
_S(438, "pidfd_getfd")
_S(439, "faccessat2")
_S(440, "process_madvise")
_S(441, "epoll_pwait2")
_S(442, "mount_setattr")
_S(443, "quotactl_fd")
_S(444, "landlock_create_ruleset")
_S(445, "landlock_add_rule")
_S(446, "landlock_restrict_self")
_S(447, "memfd_secret")
_S(448, "process_mrelease")
_S(449, "futex_waitv")
_S(450, "set_mempolicy_home_node")
_S(451, "cachestat")
_S(452, "fchmodat2")
_S(453, "map_shadow_stack")
_S(454, "futex_wake")
_S(455, "futex_wait")
_S(456, "futex_requeue")
_S(457, "statmount")
_S(458, "listmount")
_S(459, "lsm_get_self_attr")
_S(460, "lsm_set_self_attr")
_S(461, "lsm_list_modules")
_S(462, "mseal")
_S(463, "setxattrat")
_S(464, "getxattrat")
_S(465, "listxattrat")
_S(466, "removexattrat")
_S(467, "open_tree_attr")
_S(468, "file_getattr")
_S(469, "file_setattr")
