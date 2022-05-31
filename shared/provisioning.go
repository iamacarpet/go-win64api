package shared

import "errors"

type NetSetupProvisioningParams struct {
	Domain               string   `json:"domain"`
	HostName             string   `json:"hostname"`
	MachineAccountOU     string   `json:"machine_account_ou"`
	CertificateTemplates []string `json:"certificate_templates"`
	GroupPolicyObjects   []string `json:"group_policy_objects"`
}

var (
	ErrAccessDenied     = errors.New("access is denied")
	ErrExists           = errors.New("the account already exists in the domain and reuse is not enabled")
	ErrInvalidParameter = errors.New("a parameter is incorrect")
	ErrNoSuchDomain     = errors.New("the specified domain does not exist")
	ErrNotSupported     = errors.New("the request is not supported")
	ErrWorkstationSvc   = errors.New("the Workstation service has not been started")

	ErrNoOfflineJoinInfo           = errors.New("the offline join completion information was not found")
	ErrBadOfflineJoinInfo          = errors.New("the offline join completion information was bad")
	ErrCantCreateJoinInfo          = errors.New("unable to create offline join information. Please ensure you have access to the specified path location and permissions to modify its contents. Running as an elevated administrator may be required")
	ErrBadDomainJoinInfo           = errors.New("the domain join info being saved was incomplete or bad")
	ErrJoinPerformedMustRestart    = errors.New("offline join operation successfully completed but a restart is needed")
	ErrNoJoinPending               = errors.New("there was no offline join operation pending")
	ErrValuesNotSet                = errors.New("unable to set one or more requested machine or domain name values on the local computer")
	ErrCantVerifyHostname          = errors.New("could not verify the current machine's hostname against the saved value in the join completion information")
	ErrCantLoadOfflineHive         = errors.New("unable to load the specified offline registry hive. Please ensure you have access to the specified path location and permissions to modify its contents. Running as an elevated administrator may be required")
	ErrConnectionInsecure          = errors.New("the minimum session security requirements for this operation were not met")
	ErrProvisioningBlobUnsupported = errors.New("computer account provisioning blob version is not supported")
)
