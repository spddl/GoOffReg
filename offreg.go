package GoOffReg

import (
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const ( // https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
	REG_NONE                       uint32 = 0 // No value type
	REG_SZ                                = 1 // Unicode nul terminated string
	REG_EXPAND_SZ                         = 2 // Unicode nul terminated string (with environment variable references)
	REG_BINARY                            = 3 // Free form binary
	REG_DWORD                             = 4 // 32-bit number
	REG_DWORD_LITTLE_ENDIAN               = 4 // 32-bit number (same as REG_DWORD)
	REG_DWORD_BIG_ENDIAN                  = 5 // 32-bit number
	REG_LINK                              = 6 // Symbolic Link (unicode)
	REG_MULTI_SZ                          = 7 // Multiple Unicode strings
	REG_RESOURCE_LIST                     = 8 // Resource list in the resource map
	REG_FULL_RESOURCE_DESCRIPTOR          = 9 // Resource list in the hardware description
	REG_RESOURCE_REQUIREMENTS_LIST        = 10
	REG_QWORD                             = 11 // 64-bit number
	REG_QWORD_LITTLE_ENDIAN               = 11 // 64-bit number (same as REG_QWORD)
)

var (
	// Library
	offreg *windows.LazyDLL

	// Functions
	orCloseHive       *windows.LazyProc
	orCloseKey        *windows.LazyProc
	orCreateHive      *windows.LazyProc
	orCreateKey       *windows.LazyProc
	orDeleteKey       *windows.LazyProc
	orDeleteValue     *windows.LazyProc
	orEnumKey         *windows.LazyProc
	orEnumValue       *windows.LazyProc
	orGetKeySecurity  *windows.LazyProc
	orGetValue        *windows.LazyProc
	orGetVersion      *windows.LazyProc
	orGetVirtualFlags *windows.LazyProc
	orOpenHive        *windows.LazyProc
	orOpenKey         *windows.LazyProc
	orQueryInfoKey    *windows.LazyProc
	orSaveHive        *windows.LazyProc
	orSetKeySecurity  *windows.LazyProc
	orSetValue        *windows.LazyProc
	orSetVirtualFlags *windows.LazyProc
)

func init() {
	// Library
	offreg = windows.NewLazyDLL("offreg.dll")

	// Functions
	orCloseHive = offreg.NewProc("ORCloseHive")
	orCloseKey = offreg.NewProc("ORCloseKey")
	orCreateHive = offreg.NewProc("ORCreateHive")
	orCreateKey = offreg.NewProc("ORCreateKey")
	orDeleteKey = offreg.NewProc("ORDeleteKey")
	orDeleteValue = offreg.NewProc("ORDeleteValue")
	orEnumKey = offreg.NewProc("OREnumKey")
	orEnumValue = offreg.NewProc("OREnumValue")
	orGetKeySecurity = offreg.NewProc("ORGetKeySecurity")
	orGetValue = offreg.NewProc("ORGetValue")
	orGetVersion = offreg.NewProc("ORGetVersion")
	orGetVirtualFlags = offreg.NewProc("ORGetVirtualFlags")
	orOpenHive = offreg.NewProc("OROpenHive")
	orOpenKey = offreg.NewProc("OROpenKey")
	orQueryInfoKey = offreg.NewProc("ORQueryInfoKey")
	orSaveHive = offreg.NewProc("ORSaveHive")
	orSetKeySecurity = offreg.NewProc("ORSetKeySecurity")
	orSetValue = offreg.NewProc("ORSetValue")
	orSetVirtualFlags = offreg.NewProc("ORSetVirtualFlags")
}

// https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
type FileTime struct {
	dwLowDateTime  uint32
	dwHighDateTime uint32
}

type ORHKEY uintptr

const (
	ERROR_SUCCESS       = 0
	ERROR_MORE_DATA     = 234
	ERROR_NO_MORE_ITEMS = 259
)

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orclosehive
func ORCloseHive(
	// _In_ ORHKEY Handle
	handle ORHKEY,
) uint32 {
	r1, _, _ := syscall.SyscallN(orCloseHive.Addr(),
		uintptr(handle),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/oropenkey
func ORCloseKey(
	// _In_ ORHKEY Handle
	handle ORHKEY,
) uint32 {
	r1, _, _ := syscall.SyscallN(orCloseKey.Addr(),
		uintptr(handle),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orcreatehive
func ORCreateHive(
	// _Out_ PORHKEY phkResult
	phkResult *ORHKEY,
) uint32 {
	r1, _, _ := syscall.SyscallN(orCreateHive.Addr(),
		uintptr(unsafe.Pointer(phkResult)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orcreatekey
func ORCreateKey(
	// _In_      ORHKEY               Handle,
	// _In_      PCWSTR               lpSubKey,
	// _In_opt_  PWSTR                lpClass,
	// _In_opt_  DWORD                dwOptions,
	// _In_opt_  PSECURITY_DESCRIPTOR pSecurityDescriptor,
	// _Out_     PORHKEY              phkResult,
	// _Out_opt_ PDWORD               pdwDisposition
	handle ORHKEY,
	lpSubKey *uint16,
	lpName *uint16,
	dwOptions uint32,
	pSecurityDescriptor *windows.SECURITY_DESCRIPTOR,
	phkResult *ORHKEY,
	pdwDisposition *uint32,
) uint32 {
	r1, _, _ := syscall.SyscallN(orCreateKey.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(lpSubKey)),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(dwOptions),
		uintptr(unsafe.Pointer(pSecurityDescriptor)),
		uintptr(unsafe.Pointer(phkResult)),
		uintptr(unsafe.Pointer(pdwDisposition)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/ordeletekey
func ORDeleteKey(
	// _In_     ORHKEY Handle,
	// _In_opt_ PCWSTR lpSubKey
	handle ORHKEY,
	lpHivePath *uint16,
) uint32 {
	r1, _, _ := syscall.SyscallN(orDeleteKey.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(lpHivePath)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/ordeletevalue
func ORDeleteValue(
	// _In_     ORHKEY Handle,
	// _In_opt_ PCWSTR lpValueName
	handle ORHKEY,
	lpValueName *uint16,
) uint32 {
	r1, _, _ := syscall.SyscallN(orDeleteValue.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(lpValueName)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orenumkey
func OREnumKey(
	// _In_        ORHKEY    Handle,
	// _In_        DWORD     dwIndex,
	// _Out_       PWSTR     lpName,
	// _Inout_     PDWORD    lpcName,
	// _Out_opt_   PWSTR     lpClass,
	// _Inout_opt_ PDWORD    lpcClass,
	// _Out_opt_   PFILETIME lpftLastWriteTime
	handle ORHKEY,
	dwIndex uint32,
	lpName *byte,
	lpcName *uint32,
	lpClass *uint16,
	lpcClass *uint32,
	lpftLastWriteTime *FileTime,
) uint32 {
	r1, _, _ := syscall.SyscallN(orEnumKey.Addr(),
		uintptr(handle),
		uintptr(dwIndex),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(unsafe.Pointer(lpcName)),
		uintptr(unsafe.Pointer(lpClass)),
		uintptr(unsafe.Pointer(lpcClass)),
		uintptr(unsafe.Pointer(lpftLastWriteTime)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orenumvalue
func OREnumValue(
	// _In_        ORHKEY Handle,
	// _In_        DWORD  dwIndex,
	// _Out_       PWSTR  lpValueName,
	// _Inout_     PDWORD lpcValueName,
	// _Out_opt_   PDWORD lpType,
	// _Out_opt_   PBYTE  lpData,
	// _Inout_opt_ PDWORD lpcbData
	handle ORHKEY,
	dwIndex uint32,
	// lpValueName *uint16,
	lpValueName *byte,
	lpcValueName *uint32,
	lpType *uint32,
	lpData *byte,
	lpcbData *uint32,
) uint32 {
	r1, _, _ := syscall.SyscallN(orEnumValue.Addr(),
		uintptr(handle),
		uintptr(dwIndex),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(unsafe.Pointer(lpcValueName)),
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orgetkeysecurity
func ORGetKeySecurity(
	// _In_      ORHKEY               Handle,
	// _In_      SECURITY_INFORMATION SecurityInformation,
	// _Out_opt_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
	// _Inout_   PDWORD               lpcbSecurityDescriptor
	handle ORHKEY,
	dwIndex uint32,
	lpValueName *uint16,
	lpcValueName *uint32,
	lpType *uint32,
	lpData *byte,
	lpcbData *uint32,
) uint32 {
	r1, r2, err := syscall.SyscallN(orGetKeySecurity.Addr(),
		uintptr(handle),
		uintptr(dwIndex),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(unsafe.Pointer(lpcValueName)),
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)),
	)
	log.Println(r1, r2, err)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orgetvalue
func ORGetValue(
	// _In_        ORHKEY Handle,
	// _In_opt_    PCWSTR lpSubKey,
	// _In_opt_    PCWSTR lpValue,
	// _Out_opt_   PDWORD pdwType,
	// _Out_opt_   PVOID  pvData,
	// _Inout_opt_ PDWORD pcbData
	handle ORHKEY,
	lpSubKey *uint16,
	lpValue *uint16,
	pdwType *uint32,
	pvData *byte,
	pcbData *uint32,
) uint32 {
	r1, _, _ := syscall.SyscallN(orGetValue.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(lpSubKey)),
		uintptr(unsafe.Pointer(lpValue)),
		uintptr(unsafe.Pointer(pdwType)),
		uintptr(unsafe.Pointer(pvData)),
		uintptr(unsafe.Pointer(pcbData)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orgetversion
func ORGetVersion(
	// _Out_ PDWORD pdwMajorVersion,
	// _Out_ PDWORD pdwMinorVersion
	pdwMajorVersion,
	pdwMinorVersion *uint32,
) {
	syscall.SyscallN(orGetVersion.Addr(),
		uintptr(unsafe.Pointer(pdwMajorVersion)),
		uintptr(unsafe.Pointer(pdwMinorVersion)),
	)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orgetvirtualflags
func ORGetVirtualFlags(
	// _In_  ORHKEY Handle,
	// _Out_ PDWORD pdwFlags
	handle ORHKEY,
	pdwFlags *uint32,
) uint32 {
	r1, _, _ := syscall.SyscallN(orGetVirtualFlags.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(pdwFlags)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/oropenhive
func OROpenHive(
	// _In_  PCWSTR  lpHivePath,
	// _Out_ PORHKEY phkResult
	lpHivePath *uint16,
	phkResult *ORHKEY,
) uint32 {
	r1, _, _ := syscall.SyscallN(orOpenHive.Addr(),
		uintptr(unsafe.Pointer(lpHivePath)),
		uintptr(unsafe.Pointer(phkResult)),
	)

	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/oropenkey
func OROpenKey(
	// _In_     ORHKEY  Handle,
	// _In_opt_ PCWSTR  lpSubKeyName,
	// _Out_    PORHKEY phkResult
	handle ORHKEY,
	lpSubKeyName *uint16,
	phkResult *ORHKEY,
) uint32 {
	r1, _, _ := syscall.SyscallN(orOpenKey.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(lpSubKeyName)),
		uintptr(unsafe.Pointer(phkResult)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orqueryinfokey
func ORQueryInfoKey(
	// _In_        ORHKEY    Handle,
	// _Out_opt_   PWSTR     lpClass,
	// _Inout_opt_ PDWORD    lpcClass,
	// _Out_opt_   PDWORD    lpcSubKeys,
	// _Out_opt_   PDWORD    lpcMaxSubKeyLen,
	// _Out_opt_   PDWORD    lpcMaxClassLen,
	// _Out_opt_   PDWORD    lpcValues,
	// _Out_opt_   PDWORD    lpcMaxValueNameLen,
	// _Out_opt_   PDWORD    lpcMaxValueLen,
	// _Out_opt_   PDWORD    lpcbSecurityDescriptor,
	// _Out_opt_   PFILETIME lpftLastWriteTime
	handle ORHKEY,
	lpClass *uint16,
	lpcClass *uint32,
	lpcSubKeys *uint32,
	lpcMaxSubKeyLen *uint32,
	lpcMaxClassLen *uint32,
	lpcValues *uint32,
	lpcMaxValueNameLen *uint32,
	lpcMaxValueLen *uint32,
	lpcbSecurityDescriptor *uint32,
	lpftLastWriteTime *FileTime,
) uint32 {
	r1, _, _ := syscall.SyscallN(orQueryInfoKey.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(lpClass)),
		uintptr(unsafe.Pointer(lpcClass)),
		uintptr(unsafe.Pointer(lpcSubKeys)),
		uintptr(unsafe.Pointer(lpcMaxSubKeyLen)),
		uintptr(unsafe.Pointer(lpcMaxClassLen)),
		uintptr(unsafe.Pointer(lpcValues)),
		uintptr(unsafe.Pointer(lpcMaxValueNameLen)),
		uintptr(unsafe.Pointer(lpcMaxValueLen)),
		uintptr(unsafe.Pointer(lpcbSecurityDescriptor)),
		uintptr(unsafe.Pointer(lpftLastWriteTime)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orsavehive
func ORSaveHive(
	// _In_ ORHKEY Handle,
	// _In_ PCWSTR lpHivePath,
	// _In_ DWORD  dwOsMajorVersion,
	// _In_ DWORD  dwOsMinorVersion
	handle ORHKEY,
	lpHivePath *uint16,
	dwOsMajorVersion uint32,
	dwOsMinorVersion uint32,
) uint32 {
	r1, r2, err := syscall.SyscallN(orSaveHive.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(lpHivePath)),
		uintptr(dwOsMajorVersion),
		uintptr(dwOsMinorVersion),
	)
	if r1 != 0 {
		log.Println(r1, r2, err)
	}
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orsetkeysecurity
func ORSetKeySecurity(
	// _In_ ORHKEY               Handle,
	// _In_ SECURITY_INFORMATION SecurityInformation,
	// _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
	handle ORHKEY,
	SecurityInformation windows.SECURITY_INFORMATION,
	pSecurityDescriptor *windows.SECURITY_DESCRIPTOR,
) uint32 {
	r1, _, _ := syscall.SyscallN(orSetKeySecurity.Addr(),
		uintptr(handle),
		uintptr(SecurityInformation),
		uintptr(unsafe.Pointer(pSecurityDescriptor)),
	)
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orsetvalue
func ORSetValue(
	//   _In_     ORHKEY Handle,
	//   _In_opt_ PCWSTR lpValueName,
	//   _In_     DWORD  dwType,
	//   _In_opt_ const BYTE *lpData,
	//   _In_     DWORD  cbData
	handle ORHKEY,
	lpValue *uint16,
	pdwType uint32,
	pvData *byte,
	pcbData uint32,
) uint32 {
	r1, r2, err := syscall.SyscallN(orSetValue.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(lpValue)),
		uintptr(pdwType),
		uintptr(unsafe.Pointer(pvData)),
		uintptr(pcbData),
	)
	if r1 != 0 {
		log.Println(r1, r2, err)
	}
	return uint32(r1)
}

// https://docs.microsoft.com/de-de/windows/win32/devnotes/orsetvirtualflags
func ORSetVirtualFlags(
	// _In_ ORHKEY Handle,
	// _In_ DWORD  dwFlags
	handle ORHKEY,
	dwFlags uint32,
) uint32 {
	r1, _, _ := syscall.SyscallN(orSetVirtualFlags.Addr(),
		uintptr(handle),
		uintptr(dwFlags),
	)

	return uint32(r1)
}
