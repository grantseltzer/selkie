package entitlements

// Entitlement represents a grouping of system call rules
type Entitlement struct {
	Name     string   `toml:"Name,omitempty"`
	Syscalls []string `toml:"Syscalls,omitempty"`
}

// SpecialFiles describes the creation of FIFOs and special files
var SpecialFiles = Entitlement{
	Name: "special_files",
	Syscalls: []string{
		"mknod",
	},
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

var Mount = Entitlement{
	Name: "mount",
	Syscalls: []string{
		"mount",
		"umount",
		"umount2",
	},
}

var SetTime = Entitlement{
	Name: "set_time",
	Syscalls: []string{
		"ntp_adjtime",
		"adjtimex",
		"clock_adjtime",
		"clock_settime",
		"settimeofday",
		"stime",
	},
}

var Tracing = Entitlement{
	Name: "tracing",
	Syscalls: []string{
		"acct",
		"ptrace",
		"bpf",
		"perf_event_open",
	},
}

var KernelKeyring = Entitlement{
	Name: "kernel_keyring",
	Syscalls: []string{
		"add_key",
		"request_key",
		"keyctl",
	},
}

var Modules = Entitlement{
	Name: "modules",
	Syscalls: []string{
		"create_module",
		"delete_module",
		"finit_module",
		"get_kernel_syms",
		"init_module",
		"query_module",
	},
}

var LoadNewKernel = Entitlement{
	Name: "load__new_kernel",
	Syscalls: []string{
		"kexec_file_load",
		"kexec_load",
	},
}

//TODO: break up dangerous into more specific entitlements
var Dangerous = Entitlement{
	Name: "dangerous",
	Syscalls: []string{
		"clone",
		"get_mempolicy",
		"ioperm",
		"iopl",
		"lookup_dcookie",
		"mbind",
		"move_pages",
		"name_to_handle_at",
		"nfsservctl",
		"open_by_handle_at",
		"personality",
		"pivot_root",
		"process_vm_readv",
		"process_vm_writev",
		"quotactl",
		"reboot",
		"set_mempolicy",
		"setns",
		"swapon",
		"swapoff",
		"sysfs",
		"_sysctl",
		"unshare",
		"uselib",
		"userfaultfd",
		"ustat",
		"vm86",
		"vm86old",
	},
}
