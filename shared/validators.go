package shared

var DefinedProtocols = map[int]struct{}{
	6:   {},
	17:  {},
	1:   {},
	58:  {},
	256: {},
}

var DefinedAction = map[int]struct{}{
	0: {},
	1: {},
}

var DefinedProfile = map[int]struct{}{
	0:          {},
	1:          {},
	2:          {},
	3:          {},
	4:          {},
	2147483647: {},
}

var DefinedDirection = map[int]struct{}{
	1: {},
	2: {},
}

var DefinedInterfaces = map[string]struct{}{
	"LAN":          {},
	"Wireless":     {},
	"RemoteAccess": {},
	"All":          {},
}
