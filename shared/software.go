package shared

import (

)

type Software struct {
    DisplayName         string      `json:"displayName"`
    DisplayVersion      string      `json:"displayVersion"`
    Arch                string      `json:"arch"`
    Pub 		string      `json:"publisher"`
    InsDate 		string	    `json:"installDate"`
    ESize               uint64      `json:"estimatedSize"`
}

func (s *Software) Name() (string) {
    return s.DisplayName
}

func (s *Software) Version() (string) {
    return s.DisplayVersion
}

func (s *Software) Architecture() (string) {
    return s.Arch
}

func (s *Software) Publisher() (string) {
    return s.Pub
}

func (s *Software) InstallDate() (string) {
    return s.InsDate
}

func (s *Software) EstimatedSize() (uint64) {
    return s.ESize
}
