package netapi32

var (
	NetUserEnum     = modNetapi32.NewProc("NetUserEnum")
	NetUserAdd      = modNetapi32.NewProc("NetUserAdd")
	NetUserDel      = modNetapi32.NewProc("NetUserDel")
	NetGetAnyDCName = modNetapi32.NewProc("NetGetAnyDCName")
	NetUserGetInfo  = modNetapi32.NewProc("NetUserGetInfo")
	NetUserSetInfo  = modNetapi32.NewProc("NetUserSetInfo")
)

const (
	NERR_Success          = 0
	NERR_InvalidComputer  = 2351
	NERR_NotPrimary       = 2226
	NERR_SpeGroupOp       = 2234
	NERR_LastAdmin        = 2452
	NERR_BadPassword      = 2203
	NERR_PasswordTooShort = 2245
	NERR_UserNotFound     = 2221

	USER_PRIV_MASK  = 0x3
	USER_PRIV_GUEST = 0
	USER_PRIV_USER  = 1
	USER_PRIV_ADMIN = 2

	USER_FILTER_NORMAL_ACCOUNT = 0x0002
	USER_MAX_PREFERRED_LENGTH  = 0xFFFFFFFF

	USER_UF_SCRIPT             = 1
	USER_UF_ACCOUNTDISABLE     = 2
	USER_UF_LOCKOUT            = 16
	USER_UF_PASSWD_CANT_CHANGE = 64
	USER_UF_NORMAL_ACCOUNT     = 512
	USER_UF_DONT_EXPIRE_PASSWD = 65536
)

type USER_INFO_1 struct {
	Usri1_name         *uint16
	Usri1_password     *uint16
	Usri1_password_age uint32
	Usri1_priv         uint32
	Usri1_home_dir     *uint16
	Usri1_comment      *uint16
	Usri1_flags        uint32
	Usri1_script_path  *uint16
}

type USER_INFO_2 struct {
	Usri2_name           *uint16
	Usri2_password       *uint16
	Usri2_password_age   uint32
	Usri2_priv           uint32
	Usri2_home_dir       *uint16
	Usri2_comment        *uint16
	Usri2_flags          uint32
	Usri2_script_path    *uint16
	Usri2_auth_flags     uint32
	Usri2_full_name      *uint16
	Usri2_usr_comment    *uint16
	Usri2_parms          *uint16
	Usri2_workstations   *uint16
	Usri2_last_logon     uint32
	Usri2_last_logoff    uint32
	Usri2_acct_expires   uint32
	Usri2_max_storage    uint32
	Usri2_units_per_week uint32
	Usri2_logon_hours    uintptr
	Usri2_bad_pw_count   uint32
	Usri2_num_logons     uint32
	Usri2_logon_server   *uint16
	Usri2_country_code   uint32
	Usri2_code_page      uint32
}

type USER_INFO_1003 struct {
	Usri1003_password *uint16
}

type USER_INFO_1008 struct {
	Usri1008_flags uint32
}

type USER_INFO_1011 struct {
	Usri1011_full_name *uint16
}

// USER_INFO_1052 is the Go representation of the Windwos _USER_INFO_1052 struct
// used to set a user's profile directory.
//
// See: https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/ns-lmaccess-_user_info_1052
type USER_INFO_1052 struct {
	Useri1052_profile *uint16
}

type LOCALGROUP_MEMBERS_INFO_3 struct {
	Lgrmi3_domainandname *uint16
}
