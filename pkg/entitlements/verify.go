package entitlements

// defaultyDeny is a map used to keep track of the default entitlements
// that are denied (and specified to be allowed)
var defaultDeny = map[string]*Entitlement{
	SpecialFiles.Name:      &SpecialFiles,
	Chown.Name:             &Chown,
	Exec.Name:              &Exec,
	NetworkConnection.Name: &NetworkConnection,
	Mount.Name:             &Mount,
	SetTime.Name:           &SetTime,
	Tracing.Name:           &Tracing,
	KernelKeyring.Name:     &KernelKeyring,
	Modules.Name:           &Modules,
	LoadNewKernel.Name:     &LoadNewKernel,
	KernelMemory.Name:      &KernelMemory,
	KernelIO.Name:          &KernelIO,
	RootFS.Name:            &RootFS,
	Namespaces.Name:        &Namespaces,
	SwapMemory.Name:        &SwapMemory,
	Reboot.Name:            &Reboot,
	ResourceQuota.Name:     &ResourceQuota,
	obsolete.Name:          &obsolete,
}

func ValidEntitlement(entitlementName string) bool {
	if defaultDeny[entitlementName] == nil {
		return false
	}
	return true
}
