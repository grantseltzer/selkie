package entitlements

// Entitlement represents a grouping of system call rules
type Entitlement struct {
	Name     string   `toml:"Name,omitempty"`
	Syscalls []string `toml:"Syscalls,omitempty"`
}

var Stdio = Entitlement{
	Name:     "stdio",
	Syscalls: []string{
		//	clock_getres(2), clock_gettime(2), close(2), closefrom(2), dup(2), dup2(2), dup3(2), fchdir(2), fcntl(2), fstat(2), fsync(2), ftruncate(2), getdents(2), getdtablecount(2), getegid(2), getentropy(2), geteuid(2), getgid(2), getgroups(2), getitimer(2), getlogin(2), getpgid(2), getpgrp(2), getpid(2), getppid(2), getresgid(2), getresuid(2), getrlimit(2), getrtable(2), getsid(2), getthrid(2), gettimeofday(2), getuid(2), issetugid(2), kevent(2), kqueue(2), lseek(2), madvise(2), minherit(2), mmap(2), mprotect(2), mquery(2), munmap(2), nanosleep(2), pipe(2), pipe2(2), poll(2), pread(2), preadv(2), pwrite(2), pwritev(2), read(2), readv(2), recvfrom(2), recvmsg(2), select(2), sendmsg(2), sendsyslog(2), sendto(2), setitimer(2), shutdown(2), sigaction(2), sigprocmask(2), sigreturn(2), socketpair(2), umask(2), wait4(2), write(2), writev(2)
	},
}

var SpecialFiles = Entitlement{
	Name:     "special_files",
	Syscalls: []string{},
}

// Chown describes the ability to change ownership of files
// see http://man7.org/linux/man-pages/man2/chown32.2.html
var Chown = Entitlement{
	Name: "chown",
	Syscalls: []string{
		"chown",
		"fchown",
		"fchownat",
		"lchown",
	},
}

// Admin describes the system calls cap_sys_admin will grant you
// access to. Use with caution.
// see http://man7.org/linux/man-pages/man7/capabilities.7.html
var Admin = Entitlement{
	Name: "admin",
	Syscalls: []string{
		"bpf",
		"clone",
		"lookup_dcookie",
		"mount",
		"quotactl",
		"setns",
		"swapon",
		"swapoff",
		"umount",
		"umount2",
		"unshare",
		"vm86",
		"vm86old",
	},
}

// Proc includes process relationship operations
// such as forking, killing, and setting id's
var Proc = Entitlement{
	Name: "proc",
	Syscalls: []string{
		"fork",
		"vfork",
		"kill",
		"getpriority",
		"setpriority",
		"setrlimit",
		"getrlimit",
		"prlimit",
		"setpgid",
		"getpgid",
		"setpgrp",
		"getpgrp",
		"setsid",
	},
}

// Exec includes the exec, fork, and clone syscalls.
// Consider using 'Proc' instead.
var Exec = Entitlement{
	Name: "exec",
	Syscalls: []string{
		"execve",
		"execveat",
		"fork",
		"vfork",
		"clone",
	},
}

var Sockets = Entitlement{
	Name: "sockets",
	Syscalls: []string{
		"socket",
		"getsockopt",
		"setsockopt",
		"getsockname",
		"socketpair",
		"socket",
		"socketcall",
		"bind",
		"listen",
	},
}

var Dangerous = Entitlement{
	Name: "dangerous",
	Syscalls: []string{
		"acct",
		"add_key",
		"adjtimex",
		"bpf",
		"clock_adjtime",
		"clock_settime",
		"clone",
		"create_module",
		"delete_module",
		"finit_module",
		"get_kernel_syms",
		"get_mempolicy",
		"init_module",
		"ioperm",
		"iopl",
		"kcmp",
		"kexec_file_load",
		"kexec_load",
		"keyctl",
		"lookup_dcookie",
		"mbind",
		"mount",
		"move_pages",
		"name_to_handle_at",
		"nfsservctl",
		"open_by_handle_at",
		"perf_event_open",
		"personality",
		"pivot_root",
		"process_vm_readv",
		"process_vm_writev",
		"ptrace",
		"query_module",
		"quotactl",
		"reboot",
		"request_key",
		"set_mempolicy",
		"setns",
		"settimeofday",
		"socket",
		"socketcall",
		"stime",
		"swapon",
		"swapoff",
		"sysfs",
		"_sysctl",
		"umount",
		"umount2",
		"unshare",
		"uselib",
		"userfaultfd",
		"ustat",
		"vm86",
		"vm86old",
	},
}

//TODO: Add rest of entitlements
