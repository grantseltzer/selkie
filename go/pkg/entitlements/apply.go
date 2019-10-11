package entitlements

import (
	"fmt"

	"github.com/pkg/errors"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

// DenyEntitlements will disallow the capabilities described by the entitlements
// that are passed. Any system call not included in the entitlements will be allowed by default
func DenyEntitlements(entitlements []Entitlement) error {
	return applyEntitlements(entitlements, libseccomp.ActAllow, libseccomp.ActErrno)
}

// AllowEntitlements will allow the capabilities described by the entitlements
// that are passed. Any system call not included in the entitlements will be disallowed by default
func AllowEntitlements(entitlements []Entitlement) error {
	return applyEntitlements(entitlements, libseccomp.ActErrno, libseccomp.ActAllow)
}

func LogEntitlements(entitlements []Entitlement) error {
	return applyEntitlements(entitlements, libseccomp.ActErrno, libseccomp.ActLog)
}

// applyEntitlements can be used to allow or deny a set of entitlements
func applyEntitlements(entitlements []Entitlement, defaultAction, entitlementAction libseccomp.ScmpAction) error {

	fmt.Println("wut")

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
	err = filter.Load()
	if err != nil {
		return errors.Wrap(err, "could not load seccomp filter into kernel")
	}

	return nil
}
