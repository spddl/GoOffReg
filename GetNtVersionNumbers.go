package GoOffReg

import (
	"fmt"
	"syscall"
)

// GetWindowsVersion returns the Windows version information. Applications not
// manifested for Windows 8.1 or Windows 10 will return the Windows 8 OS version
// value (6.2).
//
// For a table of version numbers see:
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms724833(v=vs.85).aspx
// https://github.com/elastic/go-windows/blob/main/kernel32.go#L158
func GetWindowsVersion() (uint32, uint32) {
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms724439(v=vs.85).aspx
	ver, err := syscall.GetVersion()
	if err != nil {
		// GetVersion should never return an error.
		panic(fmt.Errorf("GetVersion failed: %v", err))
	}

	// 	return Version{
	// 		Major: int(ver & 0xFF),
	// 		Minor: int(ver >> 8 & 0xFF),
	// 		Build: int(ver >> 16),
	// 	}
	return uint32(ver & 0xFF), uint32(ver >> 8 & 0xFF)
}
