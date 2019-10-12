package entitlements

import (
	"github.com/pkg/errors"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

// DOCUMENT
// The idea is to default allow everything
// and then deny groups of 'non-standard' (i.e shit like mmap, futex)
// syscalls unless otherwise instructed.
// We don't want to break things, the added security
// of denying what will by default be denied is enough
// where it's worth it. Otherwise people won't use
// this library. Make sense?

var alreadyInstalledFilter = false

var defaultDeny = map[string]Entitlement{
	Chown.Name:        Chown,
	SpecialFiles.Name: SpecialFiles,
	Admin.Name:        Admin,
	Exec.Name:         Exec,
	Sockets.Name:      Sockets,
}

// ApplyEntitlements will allow the syscalls described by the entitlements
// that are passed.
func ApplyEntitlements(entitlements []Entitlement) error {

	for _, e := range entitlements {
		delete(defaultDeny, e.Name)
	}

	deny := []Entitlement{}
	for _, v := range defaultDeny {
		deny = append(deny, v)
	}

	return applyEntitlements(deny, libseccomp.ActAllow, libseccomp.ActErrno)
}

// applyEntitlements can be used to allow or deny a set of entitlements
func applyEntitlements(entitlements []Entitlement, defaultAction, entitlementAction libseccomp.ScmpAction) error {
	if alreadyInstalledFilter {
		return errors.New("you may only apply entitlements once")
	}

	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return err
	}

	arch, err := libseccomp.GetNativeArch()
	if err != nil {
		return errors.Wrap(err, "could not detect architecture for seccomp filter")
	}

	err = filter.AddArch(arch)
	if err != nil {
		return errors.Wrap(err, "could not add architecture to seccomp filter")
	}

	for _, e := range entitlements {
		for _, s := range e.Syscalls {

			syscall, err := libseccomp.GetSyscallFromNameByArch(s, arch)
			if err != nil {
				return errors.Wrap(err, "could not detect syscall name")
			}

			err = filter.AddRule(syscall, entitlementAction)
			if err != nil {
				return errors.Wrap(err, "could not apply syscall rule")
			}
		}
	}

	if !filter.IsValid() {
		return errors.New("invalid seccomp filter")
	}

	alreadyInstalledFilter = true
	err = filter.Load()
	if err != nil {
		return errors.Wrap(err, "could not load seccomp filter into kernel")
	}

	return nil
}
