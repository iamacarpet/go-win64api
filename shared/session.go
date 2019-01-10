package shared

import (
	"fmt"
)

type SessionDetails struct {
	Username   string `json:"username"`
	Domain     string `json:"domain"`
	LocalUser  bool   `json:"isLocal"`
	LocalAdmin bool   `json:"isAdmin"`
	LogonType  uint32 `json:"logonType"`
}

func (s *SessionDetails) FullUser() string {
	return fmt.Sprintf("%s\\%s", s.Domain, s.Username)
}
