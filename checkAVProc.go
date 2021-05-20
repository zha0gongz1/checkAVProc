package main

import (
	"fmt"
	"strings"
	"unsafe"
	"syscall"
	"os"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	Process32First = kernel32.NewProc("Process32FirstW")
	Process32Next = kernel32.NewProc("Process32NextW")
	CloseHandle = kernel32.NewProc("CloseHandle")
)

type PROCESSENTRY32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

func main() {
	EvidenceOfAV := make([]string, 0)
	antivir :=[...]string{`avp`,`avpui`}
	hProcessSnap, _, _ := CreateToolhelp32Snapshot.Call(2,0)
	if hProcessSnap < 0 {
		fmt.Println("[---] Unable to create Snapshot, exiting.")
		os.Exit(-1)
	}
	defer CloseHandle.Call(hProcessSnap)

	exeNames := make([]string, 0, 100)
	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	Process32First.Call(hProcessSnap, uintptr(unsafe.Pointer(&pe32)))

	for {

		exeNames = append(exeNames, syscall.UTF16ToString(pe32.szExeFile[:260]))

		retVal, _, _ := Process32Next.Call(hProcessSnap, uintptr(unsafe.Pointer(&pe32)))
		if retVal == 0 {
			break
		}

	}

	for _, exe := range exeNames {
		for _, avProc := range antivir {
			if (strings.Contains(strings.ToLower(exe), strings.ToLower(avProc))) {
				EvidenceOfAV = append(EvidenceOfAV, exe)
			}
		}
	}

	if len(EvidenceOfAV) == 0 {
		fmt.Println("No Kaspersky process name was found running on the system. Proceed!")
	} else {
		fmt.Printf("There is an anti-software process in the current operating environment. Do not proceed.\n%v\n", EvidenceOfAV)
	}

}