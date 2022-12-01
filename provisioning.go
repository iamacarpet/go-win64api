//go:build windows && amd64
// +build windows,amd64

package winapi

import (
	"fmt"
	"syscall"
	"unsafe"

	so "github.com/iamacarpet/shared"
)

var (
	netapi32 = syscall.NewLazyDLL("Netapi32.dll")

	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netcreateprovisioningpackage
	netCreateProvisioningPackage = netapi32.NewProc("NetCreateProvisioningPackage")
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netrequestprovisioningpackageinstall
	netRequestProvisioningPackageInstall = netapi32.NewProc("NetRequestProvisioningPackageInstall")
)

const (
	// Flags from NetCreateProvisioningPackage
	netsetupProvisioningParamsCurrentVersion = 0x00000001
	netsetupProvisionReuseAccount            = 0x00000002
	netsetupProvisionRootCACerts             = 0x00000010
	// Flags from NetRequestOfflineDomainJoin
	netsetupProvisionOnlineCaller = 0x40000000

	// Known error codes
	errnoERROR_ACCESS_DENIED         = 5
	errnoERROR_NOT_SUPPORTED         = 50
	errnoERROR_INVALID_PARAMETER     = 87
	errnoERROR_INVALID_DOMAIN_ROLE   = 1354
	errnoERROR_NO_SUCH_DOMAIN        = 1355
	errnoRPC_S_CALL_IN_PROGRESS      = 1791
	errnoRPC_S_PROTSEQ_NOT_SUPPORTED = 1703
	errnoNERR_DS8DCRequired          = 2720
	errnoNERR_LDAPCapableDCRequired  = 2721
	errnoNERR_UserExists             = 2224
	errnoNERR_WkstaNotStarted        = 2138

	errnoNERR_NoOfflineJoinInfo           = 2709
	errnoNERR_BadOfflineJoinInfo          = 2710
	errnoNERR_CantCreateJoinInfo          = 2711
	errnoNERR_BadDomainJoinInfo           = 2712
	errnoNERR_JoinPerformedMustRestart    = 2713
	errnoNERR_NoJoinPending               = 2714
	errnoNERR_ValuesNotSet                = 2715
	errnoNERR_CantVerifyHostname          = 2716
	errnoNERR_CantLoadOfflineHive         = 2717
	errnoNERR_ConnectionInsecure          = 2718
	errnoNERR_ProvisioningBlobUnsupported = 2719
)

// errnoErr converts errno return values from api calls into usable errors
func errnoErr(e syscall.Errno) error {
	switch e {
	case errnoERROR_ACCESS_DENIED:
		return so.ErrAccessDenied
	case errnoERROR_NOT_SUPPORTED:
		return so.ErrNotSupported
	case errnoERROR_INVALID_PARAMETER:
		return so.ErrInvalidParameter
	case errnoERROR_NO_SUCH_DOMAIN:
		return so.ErrNoSuchDomain
	case errnoNERR_UserExists:
		return so.ErrExists
	case errnoNERR_WkstaNotStarted:
		return so.ErrWorkstationSvc
	case errnoNERR_NoOfflineJoinInfo:
		return so.ErrNoOfflineJoinInfo
	case errnoNERR_BadOfflineJoinInfo:
		return so.ErrBadOfflineJoinInfo
	case errnoNERR_CantCreateJoinInfo:
		return so.ErrCantCreateJoinInfo
	case errnoNERR_BadDomainJoinInfo:
		return so.ErrBadDomainJoinInfo
	case errnoNERR_JoinPerformedMustRestart:
		return so.ErrJoinPerformedMustRestart
	case errnoNERR_NoJoinPending:
		return so.ErrNoJoinPending
	case errnoNERR_ValuesNotSet:
		return so.ErrValuesNotSet
	case errnoNERR_CantVerifyHostname:
		return so.ErrCantVerifyHostname
	case errnoNERR_CantLoadOfflineHive:
		return so.ErrCantLoadOfflineHive
	case errnoNERR_ConnectionInsecure:
		return so.ErrConnectionInsecure
	case errnoNERR_ProvisioningBlobUnsupported:
		return so.ErrProvisioningBlobUnsupported
	}
	return e
}

type NETSETUP_PROVISIONING_PARAMS struct {
	dwVersion           uint32
	lpDomain            *uint16
	lpHostName          *uint16
	lpMachineAccountOU  *uint16
	lpDcName            *uint16
	dwProvisionOptions  uint32
	aCertTemplateNames  uintptr
	cCertTemplateNames  uint32
	aMachinePolicyNames uintptr
	cMachinePolicyNames uint32
	aMachinePolicyPaths uintptr
	cMachinePolicyPaths uint32
	lpNetbiosName       *uint16
	lpSiteName          *uint16
	lpPrimaryDNSDomain  *uint16
}

func CreateProvisioningPackage(params *so.NetSetupProvisioningParams) ([]byte, error) {
	domainPtr, err := syscall.UTF16PtrFromString(params.Domain)
	if err != nil {
		return nil, fmt.Errorf("Unable to encode Domain to UTF16")
	}
	hostnamePtr, err := syscall.UTF16PtrFromString(params.HostName)
	if err != nil {
		return nil, fmt.Errorf("Unable to encode HostName to UTF16")
	}
	var machineOUPtr *uint16
	if len(params.MachineAccountOU) > 0 {
		machineOUPtr, err = syscall.UTF16PtrFromString(params.MachineAccountOU)
		if err != nil {
			return nil, fmt.Errorf("Unable to encode MachineAccountOU to UTF16")
		}
	}

	data := NETSETUP_PROVISIONING_PARAMS{
		dwVersion:          netsetupProvisioningParamsCurrentVersion,
		lpDomain:           domainPtr,
		lpHostName:         hostnamePtr,
		lpMachineAccountOU: machineOUPtr,
		dwProvisionOptions: netsetupProvisionReuseAccount | netsetupProvisionRootCACerts,
	}

	if len(params.CertificateTemplates) > 0 {
		certArray := []*uint16{}
		for _, k := range params.CertificateTemplates {
			certString, err := syscall.UTF16PtrFromString(k)
			if err != nil {
				return nil, fmt.Errorf("Unable to encode CertificateTemplates to UTF16")
			}
			certArray = append(certArray, certString)
		}
		data.aCertTemplateNames = uintptr(unsafe.Pointer(&certArray[0]))
		data.cCertTemplateNames = uint32(len(certArray))
	}

	if len(params.GroupPolicyObjects) > 0 {
		gpoArray := []*uint16{}
		for _, k := range params.GroupPolicyObjects {
			gpoString, err := syscall.UTF16PtrFromString(k)
			if err != nil {
				return nil, fmt.Errorf("Unable to encode GroupPolicyObjects to UTF16")
			}
			gpoArray = append(gpoArray, gpoString)
		}
		data.aMachinePolicyNames = uintptr(unsafe.Pointer(&gpoArray[0]))
		data.cMachinePolicyNames = uint32(len(gpoArray))
	}

	var (
		buff    uintptr
		binSize uint32
	)

	r, _, err := netCreateProvisioningPackage.Call(
		uintptr(unsafe.Pointer(&data)),    //_In_      PNETSETUP_PROVISIONING_PARAMS pProvisioningParams
		uintptr(unsafe.Pointer(&buff)),    //_Out_opt_ PBYTE   *ppPackageBinData
		uintptr(unsafe.Pointer(&binSize)), //_Out_opt_ DWORD   *ppPackageBinData
		0,                                 //_Out_opt_ LPWSTR  *ppPackageTextData
	)
	if r != 0 {
		return nil, errnoErr(syscall.Errno(r))
	}

	// Up to 10MB: 10485760 bytes
	return (*[10485760]byte)(unsafe.Pointer(buff))[:binSize], nil
}

func RequestProvisioningPackageInstall(data []byte) error {
	ptrWindows, err := syscall.UTF16PtrFromString("C:\\Windows")
	if err != nil {
		return err
	}

	dataLength := uint32(len(data))

	var options uint32 = netsetupProvisionOnlineCaller

	r, _, err := netRequestProvisioningPackageInstall.Call(
		uintptr(unsafe.Pointer(&data[0])),   //_In_      BYTE    *pPackageBinData
		uintptr(dataLength),                 //_In_      DWORD   dwPackageBinDataSize
		uintptr(options),                    //_In_      DWORD   dwProvisionOptions
		uintptr(unsafe.Pointer(ptrWindows)), //_In_      LPCWSTR lpWindowsPath
		0,                                   //          PVOID   pvReserved
	)
	if r != 0 {
		return errnoErr(syscall.Errno(r))
	}

	return nil
}
