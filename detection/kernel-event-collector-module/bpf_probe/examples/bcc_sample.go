//
// Copyright 2020-20201 VMware, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

// This holds complete C program
var cProgramCode string

//# List of deprecated functions and number of the replacement functions
//# while adding the Probe, its important to add the deprecated function
//# and their replacement function(s) in order.
//# See example of deprecated function __vfs_write below.
//# 2 Replacement functions (viz: vfs_write, __kernel_write)

var deprecatedFuncMap = map[string]int{"__vfs_write": 2}

type probeMeta struct {
	PP          string
	PPCbName    string
	IsKretProbe bool
}

var allProbes = []probeMeta{
	//# PID Clone Events
	probeMeta{
		PP:          "wake_up_new_task",
		PPCbName:    "on_wake_up_new_task",
		IsKretProbe: false,
	},
	//# cache eviction relate probe
	probeMeta{
		PP:          "security_file_free",
		PPCbName:    "on_security_file_free",
		IsKretProbe: false,
	},

	//# Process Exit Events
	probeMeta{
		PP:          "security_task_free",
		PPCbName:    "on_security_task_free",
		IsKretProbe: false,
	},

	//# File Events
	probeMeta{
		PP:          "__vfs_write",
		PPCbName:    "trace_write_entry",
		IsKretProbe: false,
	},
	//# Note, the 2 probe points below. They are replacements of
	//# __vfs_write for kernel version >= 5.8.0
	//# We need to attach either __vfs_write OR vfs_write, __kernel_write
	//# Insert any new probes after __kernel_write
	probeMeta{
		PP:          "vfs_write",
		PPCbName:    "trace_write_entry",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "__kernel_write",
		PPCbName:    "trace_write_kentry",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "security_mmap_file",
		PPCbName:    "on_security_mmap_file",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "security_file_open",
		PPCbName:    "on_security_file_open",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "security_inode_unlink",
		PPCbName:    "on_security_inode_unlink",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "security_inode_rename",
		PPCbName:    "on_security_inode_rename",
		IsKretProbe: false,
	},

	//# execve and execveat syscalls
	probeMeta{
		PP:          bpf.GetSyscallFnName("execve"),
		PPCbName:    "syscall__on_sys_execve",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          bpf.GetSyscallFnName("execveat"),
		PPCbName:    "syscall__on_sys_execveat",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          bpf.GetSyscallFnName("execve"),
		PPCbName:    "after_sys_execve",
		IsKretProbe: true,
	},
	probeMeta{
		PP:          bpf.GetSyscallFnName("execveat"),
		PPCbName:    "after_sys_execve",
		IsKretProbe: true,
	},

	//# DNS TCP Network Events
	probeMeta{
		PP:          "tcp_sendmsg",
		PPCbName:    "trace_tcp_sendmsg",
		IsKretProbe: false,
	},

	//# DNS UDP recvmsg Events
	probeMeta{
		PP:          "udp_recvmsg",
		PPCbName:    "trace_udp_recvmsg",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "udpv6_recvmsg",
		PPCbName:    "trace_udp_recvmsg",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "udp_recvmsg",
		PPCbName:    "trace_udp_recvmsg_return",
		IsKretProbe: true,
	},
	probeMeta{
		PP:          "udpv6_recvmsg",
		PPCbName:    "trace_udp_recvmsg_return",
		IsKretProbe: true,
	},

	//# UDP Tx Events
	probeMeta{
		PP:          "udp_sendmsg",
		PPCbName:    "trace_udp_sendmsg",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "udpv6_sendmsg",
		PPCbName:    "trace_udp_sendmsg",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "udp_sendmsg",
		PPCbName:    "trace_udp_sendmsg_return",
		IsKretProbe: true,
	},
	probeMeta{
		PP:          "udpv6_sendmsg",
		PPCbName:    "trace_udp_sendmsg_return",
		IsKretProbe: true,
	},

	//# UDP Rx Events
	probeMeta{
		PP:          "__skb_recv_udp",
		PPCbName:    "trace_skb_recv_udp",
		IsKretProbe: true,
	},

	//# TCP Connect Events
	probeMeta{
		PP:          "tcp_v4_connect",
		PPCbName:    "trace_connect_v4_entry",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "tcp_v6_connect",
		PPCbName:    "trace_connect_v6_entry",
		IsKretProbe: false,
	},
	probeMeta{
		PP:          "tcp_v4_connect",
		PPCbName:    "trace_connect_v4_return",
		IsKretProbe: true,
	},
	probeMeta{
		PP:          "tcp_v6_connect",
		PPCbName:    "trace_connect_v6_return",
		IsKretProbe: true,
	},

	//# TCP Accept Events
	probeMeta{
		PP:          "inet_csk_accept",
		PPCbName:    "trace_accept_return",
		IsKretProbe: true,
	},
}

// LocalAddr  is in union with LocalAddr6
// RemoteAddr is in union with RemoteAddr6
type netEventData struct {
	LocalAddr   uint32
	RemoteAddr  uint32
	RemotePort  uint16
	LocalPort   uint16
	IPVer       uint16
	Proto       uint16
	DNSFlag     uint16
	Pad         uint16
	LocalAddr6  [4]uint32
	RemoteAddr6 [4]uint32
	DNS         [40]byte
	NameLen     uint32
}

type mmapArgs struct {
	flags uint64
	prot  uint64
}

// Global structure read from the kernel event
// use Capital letter to start attributes
// Add Padded bytes to care of alignment (struct data_t)
type sensorEvent struct {
	EventTime uint64
	Tid       uint32
	Pid       uint32
	EvType    uint8
	State     uint8
	Pad1      uint16
	UID       uint32
	Ppid      uint32
	Inode     uint64
	Device    uint32
	MntNS     uint32
	Pad2      [4]byte
	Ufname    [255]byte
	Pad3      byte
	RetVal    int32
	StartTime uint64
}

/////////////////////
// main functionality
/////////////////////

func main() {

	const perfMapPageCnt = 1024

	fileName := string("src/bcc_sensor.c")
	if len(os.Args) > 2 {
		fmt.Println("Usage:", os.Args[0], " <C source code file> e.g. src/bcc_sensor.c")
		return
	}
	if len(os.Args) == 2 {
		fileName = os.Args[1]
	}
	if checkPrivileges() != true {
		fmt.Println("Insufficient privileges. Can not load BPF program code.")
		return
	}

	if loadScript(fileName) != true {
		return
	}

	bpfMod := bpf.NewModule(cProgramCode, []string{})
	defer bpfMod.Close()

	attachProbes(bpfMod)

	// TableId commes from BPF_PERF_OUTPUT
	eventTable := bpf.NewTable(bpfMod.TableId("events"), bpfMod)

	cloneEventTable = make(map[string]*cloneEvent)
	execEventTable = make(map[uint32]*execEvent)
	fileEventTable = make(map[string]*fileEvent)

	eventChannel := make(chan []byte)

	sensorMap, err := bpf.InitPerfMapWithPageCnt(eventTable, eventChannel, nil, perfMapPageCnt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Perf map Initialization failed: %s\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "Waiting for events... ^C to stop.\n\n")
	interruptSignal := make(chan os.Signal, 1)
	signal.Notify(interruptSignal, os.Interrupt, os.Kill)

	go func() {
		var kevent sensorEvent
		for {
			eventData := <-eventChannel
			//fmt.Fprintf(os.Stdout, "Raw len %d : %+v\n", len(eventData), eventData)
			err := binary.Read(bytes.NewBuffer(eventData), binary.LittleEndian, &kevent)
			if err != nil {
				fmt.Printf("Event decode failed error : %s\n", err)
				continue
			}
			parsePrintEvent(kevent)
		}
	}()

	sensorMap.Start()
	<-interruptSignal
	sensorMap.Stop()
}

func checkPrivileges() bool {
	// cap checks TODO
	return true
}

func loadScript(fileName string) bool {
	// file sanity checks
	statData, err := os.Stat(fileName)
	if os.IsNotExist(err) || statData.IsDir() {
		fmt.Fprintf(os.Stderr, "File %s does not exist. err: %s\n", fileName, err)
		return false
	}
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Reading file Failed : %s\n", err)
		return false
	}
	cProgramCode = string(fileData)
	return true
}

func attachProbes(bpfMod *bpf.Module) int32 {
	depFuncSkipFlag := 0

	for i := 0; i < len(allProbes); i++ {
		if depFuncSkipFlag > 0 {
			depFuncSkipFlag--
			continue
		}
		if count, found := deprecatedFuncMap[allProbes[i].PP]; found {
			if checkSymbolExists(allProbes[i].PP) {
				depFuncSkipFlag = count
			} else {
				continue
			}
		}

		currKprobe, err := bpfMod.LoadKprobe(allProbes[i].PPCbName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load kprobe Failed : %s\n", err)
			return 1
		}

		if allProbes[i].IsKretProbe == false {
			err = bpfMod.AttachKprobe(allProbes[i].PP, currKprobe, -1)
		} else {
			err = bpfMod.AttachKretprobe(allProbes[i].PP, currKprobe, -1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Attach kprobe failed to : %s\n", err)
			return 1
		}
		//fmt.Fprintf(os.Stdout, "Kprobe [%d] %s Ret %t\n", i,
		//			allProbes[i].PP, allProbes[i].IsKretProbe)
	}
	fmt.Fprintf(os.Stdout, "\nSuccessfully attached kprobes !!!\n")
	return 0
}

func checkSymbolExists(symbol string) bool {
	fileData, err := ioutil.ReadFile("/proc/kallsyms")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Reading kallsyms Failed : %s\n", err)
		return false
	}
	allsymsString := string(fileData)
	return strings.Contains(allsymsString, symbol)
}

//////////////////////
// Enum, Constants etc
//////////////////////

const (
	evProcessArg    = 0
	evProcessExec   = 1
	evProcessExit   = 2
	evProcessClone  = 3
	evFileRead      = 4
	evFileWrite     = 5
	evFileCreate    = 6
	evFilePath      = 7
	evFileMmap      = 8
	evFileTest      = 9
	evConnectPre    = 10
	evConnectAccept = 11
	evDNSResponse   = 12
	evWebProxy      = 13
	evFileDelete    = 14
	evFileClose     = 15
	evFileOpen	= 16
)

type stateType uint8

const (
	stPpNoExtraData   = 0
	stPpEntryPoint    = 1
	stPpPathComponent = 2
	stPpFinalized     = 3
	stPpAppend        = 4
	stPpDebug         = 5
)

func printEventByType(eventType uint8) string {
	eventNames := [...]string{
		"PROCESS_ARG",
		"PROCESS_EXEC",
		"PROCESS_EXIT",
		"PROCESS_CLONE",
		"FILE_READ",
		"FILE_WRITE",
		"FILE_CREATE",
		"FILE_PATH",
		"FILE_MMAP",
		"FILE_TEST",
		"NET_CONNECT",
		"NET_ACCEPT",
		"DNS_RESPONSE",
		"WEB_PROXY",
		"FILE_DELETE",
		"FILE_CLOSE",
		"FILE_OPEN"}
	if len(eventNames) >= int(eventType) {
		return eventNames[eventType]
	}
	return "UNKNOWN"
}

//////////////////////
// event parsing logic
//////////////////////

func parsePrintEvent(kevent sensorEvent) {
	var result string

	switch kevent.EvType {
	case evProcessClone:
		result = handleCloneEvent(kevent)

	case evProcessExit:
		result = handleExitEvent(kevent)

	case evProcessExec, evProcessArg:
		result = handleExecEvent(kevent)

	case evConnectPre, evConnectAccept:
		result = handleNetworkEvent(kevent)

	case evDNSResponse, evWebProxy:
		result = handleDNSEvent(kevent)

	case evFileWrite, evFileMmap, evFileCreate, evFileDelete, evFileClose, evFileOpen:
		result = handleFileEvent(kevent)
	}
	if len(result) > 0 {
		fmt.Printf("%s.\n", result)
	}
}

///////////////
// cloneEvent
///////////////

type cloneEvent struct {
	filePath string

	eventTime uint64
	tid       uint32
	pid       uint32
	uid       uint32
	startTime uint64
	ppid      uint32
	inode     uint64
	device    uint32
	mntNS     uint32
	comm      string
}

// Table for key, value pairs
var cloneEventTable map[string]*cloneEvent

func (clone *cloneEvent) initFunc(eventMsg sensorEvent) {
	clone.filePath = ""

	clone.eventTime = eventMsg.EventTime
	clone.tid = eventMsg.Tid
	clone.pid = eventMsg.Pid
	clone.uid = eventMsg.UID
	clone.startTime = eventMsg.StartTime
	clone.ppid = eventMsg.Ppid
	clone.inode = eventMsg.Inode
	clone.device = eventMsg.Device
	clone.mntNS = eventMsg.MntNS
	clone.comm = eventMsgfNameDecode(eventMsg)
}

func (clone cloneEvent) logstrFunc() string {
	pathStr := clone.filePath
	if len(pathStr) == 0 {
		pathStr = clone.comm
	}
	cloneEventStr := fmt.Sprintf("%d FORK pid:%d ppid:%d uid:%d start_time:%d mnt_ns:%d [%x:%d]%s",
		clone.eventTime,
		clone.pid,
		clone.ppid,
		clone.uid,
		clone.startTime,
		clone.mntNS,
		clone.device,
		clone.inode,
		pathStr)
	return cloneEventStr
}

func handleCloneEvent(kevent sensorEvent) string {
	key := fmt.Sprintf("%d-%d", kevent.EventTime, kevent.Pid)
	if kevent.State == stPpNoExtraData {
		forkStr := fmt.Sprintf("%d FORK pid:%d ppid:%d uid:%d start_time:%d %s",
			kevent.EventTime,
			kevent.Pid,
			kevent.Ppid,
			kevent.UID,
			kevent.StartTime,
			eventMsgfNameDecode(kevent))
		if _, found := cloneEventTable[key]; found {
			delete(cloneEventTable, key)
		}
		return forkStr
	} else if kevent.State == stPpEntryPoint {
		if _, found := cloneEventTable[key]; found {
			fmt.Fprintf(os.Stderr, "Key shouldn't exist\n")
			delete(cloneEventTable, key)
		}
		var clone cloneEvent
		clone.initFunc(kevent)
		cloneEventTable[key] = &clone
		return ""
	}

	if _, found := cloneEventTable[key]; !found {
		fmt.Fprintf(os.Stderr, "Missing clone event entry\n")
		return ""
	}

	if kevent.State == stPpPathComponent {
		clone, _ := cloneEventTable[key]
		clone.filePath = fmt.Sprintf("/%s%s", eventMsgfNameDecode(kevent), clone.filePath)
	} else if kevent.State == stPpFinalized {
		clone, _ := cloneEventTable[key]
		delete(cloneEventTable, key)
		return clone.logstrFunc()
	}
	return ""
}

func handleExitEvent(kevent sensorEvent) string {
	exitStr := fmt.Sprintf("%d EXIT pid:%d start_time:%d",
		kevent.EventTime, kevent.Pid, kevent.StartTime)
	return exitStr
}

///////////////
// execEvent
///////////////

type execEvent struct {
	retVal            int32
	finalizeFilePath  bool
	setEntrypointData bool
	scriptPath        string
	filePath          string

	eventTime uint64
	tid       uint32
	pid       uint32
	argStr    string
	startTime uint64
	ppid      uint32
	uid       uint32
	inode     uint64
	device    uint32
	mntNS     uint32
}

// Table for key, value pairs
var execEventTable map[uint32]*execEvent

func (exec *execEvent) initFunc(eventMsg sensorEvent) {
	exec.retVal = -1
	exec.finalizeFilePath = false
	exec.setEntrypointData = false
	exec.scriptPath = ""
	exec.filePath = ""

	exec.eventTime = eventMsg.EventTime
	exec.tid = eventMsg.Tid
	exec.pid = eventMsg.Pid
	exec.argStr = eventMsgfNameDecode(eventMsg)
	exec.startTime = 0
	exec.ppid = 0
	exec.uid = 0
	exec.inode = 0
	exec.device = 0
	exec.mntNS = 0
}

func (exec *execEvent) updateFunc(eventMsg sensorEvent) string {
	if eventMsg.EvType == evProcessArg {
		if eventMsg.State == stPpFinalized {
			exec.retVal = eventMsg.RetVal
			return exec.logstrFunc()
		} else if eventMsg.State == stPpEntryPoint {
			exec.argStr += " " + eventMsgfNameDecode(eventMsg)
		} else if eventMsg.State == stPpAppend {
			exec.argStr += eventMsgfNameDecode(eventMsg)
		}
	}
	if eventMsg.EvType == evProcessExec {
		if eventMsg.State == stPpEntryPoint {
			exec.startTime = eventMsg.StartTime
			exec.ppid = eventMsg.Ppid
			exec.uid = eventMsg.UID
			exec.inode = eventMsg.Inode
			exec.device = eventMsg.Device
			exec.mntNS = eventMsg.MntNS
		} else if eventMsg.State == stPpPathComponent {
			exec.filePath = fmt.Sprintf("/%s%s", eventMsgfNameDecode(eventMsg), exec.filePath)
		} else if eventMsg.State == stPpFinalized {
			exec.finalizeFilePath = true
		}
	}
	return ""
}

func (exec execEvent) logstrFunc() string {
	//args = exec.argStr
	execEventStr := fmt.Sprintf("%d EXEC pid:%d ppid:%d uid:%d start_time:%d mnt_ns:%d [%x:%d]%s ret:%d \"%s\"",
		exec.eventTime,
		exec.pid,
		exec.ppid,
		exec.uid,
		exec.startTime,
		exec.mntNS,
		exec.device,
		exec.inode,
		exec.filePath,
		exec.retVal,
		exec.argStr)
	return execEventStr
}

func handleExecEvent(kevent sensorEvent) string {
	key := kevent.Tid
	if exec, found := execEventTable[key]; found {
		result := exec.updateFunc(kevent)
		if len(result) > 0 {
			delete(execEventTable, key)
			return result
		}
	} else {
		var exec execEvent
		exec.initFunc(kevent)
		execEventTable[key] = &exec
	}
	return ""
}

///////////////
// netEvent
///////////////

type netEvent struct {
	eventTime      uint64
	tid            uint32
	pid            uint32
	ppid           uint32
	startTime      uint64
	mntNS          uint32
	uid            uint32
	eventTypeStr   string
	flow           string
	family         string
	packLocalAddr  string
	packRemoteAddr string
	proto          string
	localPort      uint16
	remotePort     uint16
}

func (net *netEvent) initFunc(eventMsg sensorEvent) {
	net.eventTime = eventMsg.EventTime
	net.tid = eventMsg.Tid
	net.pid = eventMsg.Pid

	net.ppid = eventMsg.Ppid
	net.startTime = eventMsg.StartTime
	net.mntNS = eventMsg.MntNS
	//# Not in 4.4 suse kernels
	net.uid = eventMsg.UID

	net.eventTypeStr = printEventByType(eventMsg.EvType)

	net.flow = ""
	net.family = ""
	net.packLocalAddr = ""
	net.packRemoteAddr = ""
	net.proto = "TCP"

	var netEvent netEventData
	err := binary.Read(bytes.NewBuffer(eventMsg.Ufname[:]), binary.LittleEndian, &netEvent)
	if err != nil {
		fmt.Printf("netEvent decode failed error : %s\n", err)
		return
	}

	if netEvent.Proto == 17 {
		net.proto = "UDP"
	}

	net.localPort = ntohs(netEvent.LocalPort)
	net.remotePort = ntohs(netEvent.RemotePort)

	if eventMsg.EvType == evConnectAccept {
		net.flow = "rx"
	} else if eventMsg.EvType == evConnectPre {
		net.flow = "tx"
	}

	//# AF_INET : IPVer = 2 ... defined in linux/socket.h
	bytesLocal := make([]byte, 4)
	bytesRemote := make([]byte, 4)
	if netEvent.IPVer == 2 {
		net.family = "IPv4"
		binary.LittleEndian.PutUint32(bytesLocal, netEvent.LocalAddr)
		net.packLocalAddr = fmt.Sprintf("%d.%d.%d.%d",
			bytesLocal[0], bytesLocal[1], bytesLocal[2], bytesLocal[3])
		binary.LittleEndian.PutUint32(bytesRemote, netEvent.RemoteAddr)
		net.packRemoteAddr = fmt.Sprintf("%d.%d.%d.%d",
			bytesRemote[0], bytesRemote[1], bytesRemote[2], bytesRemote[3])
		//# AF_INET6 : IPVer = 10
	} else if netEvent.IPVer == 10 {
		net.family = "IPv6"
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(bytesLocal, netEvent.LocalAddr6[i])
			binary.LittleEndian.PutUint32(bytesRemote, netEvent.RemoteAddr6[i])
			net.packLocalAddr = fmt.Sprintf("%s%d.%d.%d.%d", net.packLocalAddr,
				bytesLocal[0], bytesLocal[1], bytesLocal[2], bytesLocal[3])
			net.packRemoteAddr = fmt.Sprintf("%s%d.%d.%d.%d", net.packRemoteAddr,
				bytesRemote[0], bytesRemote[1], bytesRemote[2], bytesRemote[3])
		}
	} else {
		net.family = "IPv4"
		net.packLocalAddr = "0"
		net.packRemoteAddr = "0"
	}
}

func ntohs(src uint16) uint16 {
	bytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(bytes, src)
	return binary.BigEndian.Uint16(bytes)
}

func (net netEvent) logstrFunc() string {
	netEventStr := fmt.Sprintf("%d %s %s  pid:%d %s:%d -> %s:%d",
		net.eventTime,
		net.eventTypeStr,
		net.proto,
		net.pid,
		net.packLocalAddr,
		net.localPort,
		net.packRemoteAddr,
		net.remotePort)
	return netEventStr
}

func handleNetworkEvent(kevent sensorEvent) string {
	var net netEvent
	net.initFunc(kevent)
	return net.logstrFunc()
}

func handleDNSEvent(kevent sensorEvent) string {
	return ""
}

///////////////
// fileEvent
///////////////

type fileEvent struct {
	filePath string
	mounts   map[uint32]string

	evType       uint8
	eventTime    uint64
	tid          uint32
	pid          uint32
	ppid         uint32
	uid          uint32
	inode        uint64
	device       uint32
	mntNS        uint32
	eventTypeStr string
}

// Table for key, value pairs
var fileEventTable map[string]*fileEvent

func (file *fileEvent) initFunc(eventMsg sensorEvent) {
	file.filePath = ""
	file.mounts = make(map[uint32]string)

	file.evType = eventMsg.EvType
	file.eventTime = eventMsg.EventTime
	file.tid = eventMsg.Tid
	file.pid = eventMsg.Pid
	file.ppid = eventMsg.Ppid
	file.uid = eventMsg.UID
	file.inode = eventMsg.Inode
	file.device = eventMsg.Device
	file.mntNS = eventMsg.MntNS
	file.eventTypeStr = printEventByType(eventMsg.EvType)
}

func getMounts(mounts map[uint32]string) {
	mountFile, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening mountinfo\n")
		return
	}
	defer mountFile.Close()
	lineReader := bufio.NewScanner(mountFile)
	for lineReader.Scan() {
		lineStr := lineReader.Text()
		parts := strings.Split(lineStr, " ")
		dev := strings.Split(parts[2], ":")
		MSB, _ := strconv.Atoi(dev[0])
		LSB, _ := strconv.Atoi(dev[1])
		devNum := uint32((MSB << 8) | LSB)
		mounts[devNum] = parts[4][1:]
	}
}

func (file *fileEvent) updateFunc(eventMsg sensorEvent) string {
	if eventMsg.State == stPpPathComponent {
		name := eventMsgfNameDecode(eventMsg)
		if len(name) == 0 {
			if len(file.mounts) == 0 {
				getMounts(file.mounts)
			}
			if mount, found := file.mounts[file.device]; found {
				name = mount
			}
		}
		file.filePath = fmt.Sprintf("/%s%s", name, file.filePath)
	} else if eventMsg.State == stPpFinalized {
		return file.logstrFunc()
	}
	return ""
}

func (file fileEvent) logstrFunc() string {
	fileEventStr := fmt.Sprintf("%d %s pid:%d ppid:%d uid:%d mnt_ns:%d [%x:%d]%s",
		file.eventTime,
		file.eventTypeStr,
		file.pid,
		file.ppid,
		file.uid,
		file.mntNS,
		file.device,
		file.inode,
		file.filePath)
	return fileEventStr
}

func handleFileEvent(kevent sensorEvent) string {
	key := fmt.Sprintf("%d-%d", kevent.Tid, kevent.EventTime)
	if file, found := fileEventTable[key]; found {
		if file.evType != kevent.EvType {
			fmt.Fprintf(os.Stderr, "Miss-match of file event types\n")
			return ""
		}

		result := file.updateFunc(kevent)
		if len(result) != 0 {
			delete(fileEventTable, key)
			return result
		}
	} else {
		if kevent.State > stPpEntryPoint {
			fmt.Fprintf(os.Stderr, "Missing event data\n")
		}
		var file fileEvent
		file.initFunc(kevent)
		fileEventTable[key] = &file
	}
	return ""
}

func eventMsgfNameDecode(eventMsg sensorEvent) string {
	var fName [255]byte
	i := 0

	for j := 0; j < len(eventMsg.Ufname); j++ {
		// max index for i = 254
		if eventMsg.Ufname[j] == 0 || i == 254 {
			break
		}
		fName[i] = eventMsg.Ufname[j]
		i++
	}
	fName[i] = 0
	return string(fName[:i])
}
