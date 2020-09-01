// +build windows,amd64

package advapi32

var (
	LookupAccountNameW     = modAdvapi32.NewProc("LookupAccountNameW")
	ConvertSidToStringSidW = modAdvapi32.NewProc("ConvertSidToStringSidW")
)
