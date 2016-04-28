package shared

import (
    
)

type Software struct {
    DisplayName         string      `json:"displayName"`
    DisplayVersion      string      `json:"displayVersion"`
    Arch                string      `json:"arch"`
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
