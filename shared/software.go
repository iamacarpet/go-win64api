package shared

import (

)

type Software struct {
    R_DisplayName         string      `json:"displayName"`
    R_DisplayVersion      string      `json:"displayVersion"`
    R_Arch                string      `json:"arch"`
    R_Pub 		            string      `json:"publisher"`
    R_InsDate 		        string      `json:"installDate"`
    R_ESize               uint64      `json:"estimatedSize"`
    R_Contact		          string      `json:"Contact"`
    R_HelpLink		        string      `json:"HelpLink"`
    R_InstallSource       string      `json:"InstallSource"`
    R_VersionMajor        uint64      `json:"VersionMajor"`
    R_VersionMinor 	      uint64      `json:"VersionMinor"`
}

func (s *Software) Name() (string) {
    return s.R_DisplayName
}

func (s *Software) Version() (string) {
    return s.R_DisplayVersion
}

func (s *Software) Architecture() (string) {
    return s.R_Arch
}

func (s *Software) Publisher() (string) {
    return s.R_Pub
}

func (s *Software) InstallDate() (string) {
    return s.R_InsDate
}

func (s *Software) EstimatedSize() (uint64) {
    return s.R_ESize
}

func (s *Software) Contact() (string) {
    return s.R_Contact
}

func (s *Software) HelpLink() (string) {
    return s.R_HelpLink
}

func (s *Software) InstallSource() (string) {
    return s.R_InstallSource
}

func (s *Software) VersionMajor() (uint64) {
    return s.R_VersionMajor
}

func (s *Software) VersionMinor() (uint64) {
    return s.R_VersionMinor
}
