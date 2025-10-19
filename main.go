package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// --- Win32 API 構造体と定数の定義 ---
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}
type MIB_TCPTABLE_OWNER_PID struct {
	NumEntries uint32
	Table      [1]MIB_TCPROW_OWNER_PID
}
var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

// --- アプリケーションの構造体定義 ---
type TCPConnection struct {
	ProcessName string
	PID         uint32
	LocalAddr   string
	LocalPort   uint16
	RemoteAddr  string
	RemotePort  uint16
	State       string
}

// --- メインロジック ---
func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "monitor":
		runMonitorMode()
	case "snapshot":
		runSnapshotMode()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "使用方法: %s <サブコマンド> [オプション]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "サブコマンド:")
	fmt.Fprintln(os.Stderr, "  monitor    接続の状態変化 (新規、変化、終了) を監視します。")
	fmt.Fprintln(os.Stderr, "  snapshot   指定した間隔で、現在の全接続状態をスナップショットとして表示します。")
	fmt.Fprintln(os.Stderr, "\n各サブコマンドのオプションは -h で確認できます。")
	fmt.Fprintf(os.Stderr, "例: %s monitor -n java.exe -i 200\n", os.Args[0])
}

// 共通のコマンドラインフラグを設定 (ミリ秒単位に変更)
func setupFlags(fs *flag.FlagSet) (*string, *string, *string, *int) {
	processNames := fs.String("n", "", "監視するプロセス名 (カンマ区切り)")
	pids := fs.String("p", "", "監視するPID (カンマ区切り, '0'でデバッグモード)")
	outputFile := fs.String("o", "", "出力ファイル名")
	intervalMilliseconds := fs.Int("i", 1000, "実行間隔(ミリ秒)") // 秒からミリ秒に変更
	return processNames, pids, outputFile, intervalMilliseconds
}

// --- monitor モード ---
func runMonitorMode() {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	processNames, pids, outputFile, intervalMilliseconds := setupFlags(fs)
	fs.Parse(os.Args[2:])

	targets, debugMode, monitorTarget := processArgs(*processNames, *pids)
	setupLogging(*outputFile)

	log.Printf("--- 監視モード開始 ---")
	log.Printf("監視対象: %s", monitorTarget)
	log.Printf("実行間隔: %d ミリ秒... (Ctrl+Cで停止)", *intervalMilliseconds)

	prevConns := make(map[string]TCPConnection)
	ticker := time.NewTicker(time.Duration(*intervalMilliseconds) * time.Millisecond) // ミリ秒に変更
	defer ticker.Stop()

	for range ticker.C {
		currentConns, err := getFilteredConnections(targets, debugMode)
		if err != nil {
			log.Printf("エラー: 接続情報の取得に失敗: %v", err)
			continue
		}
		detectAndLogChanges(currentConns, prevConns)
		prevConns = currentConns
	}
}

// --- snapshot モード ---
func runSnapshotMode() {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	processNames, pids, outputFile, intervalMilliseconds := setupFlags(fs)
	fs.Parse(os.Args[2:])

	targets, debugMode, monitorTarget := processArgs(*processNames, *pids)
	setupLogging(*outputFile)

	log.Printf("--- スナップショットモード開始 ---")
	log.Printf("監視対象: %s", monitorTarget)
	log.Printf("実行間隔: %d ミリ秒... (Ctrl+Cで停止)", *intervalMilliseconds)

	ticker := time.NewTicker(time.Duration(*intervalMilliseconds) * time.Millisecond) // ミリ秒に変更
	defer ticker.Stop()

	for currentTime := range ticker.C {
		currentConns, err := getFilteredConnections(targets, debugMode)
		if err != nil {
			log.Printf("エラー: 接続情報の取得に失敗: %v", err)
			continue
		}

		if len(currentConns) == 0 {
			log.Printf("--- %s 監視対象に一致する接続は見つかりません ---", currentTime.Format("15:04:05"))
		} else {
			var report strings.Builder
			report.WriteString(fmt.Sprintf("--- %s 監視対象の接続 (%d件) ---\n", currentTime.Format("15:04:05"), len(currentConns)))
			for key, conn := range currentConns {
				report.WriteString(fmt.Sprintf("%s | Process: %-15s (PID: %-5d) | 状態: %-12s\n", key, conn.ProcessName, conn.PID, conn.State))
			}
			report.WriteString("-----------------------------------")
			log.Println(report.String())
		}
	}
}

// --- 共通ロジック (以降は変更なし) ---
func processArgs(processNames, pids string) (targets []string, debugMode bool, monitorTarget string) {
	if processNames == "" && pids == "" {
		fmt.Fprintln(os.Stderr, "エラー: -n または -p のどちらかを必ず指定してください。")
		os.Exit(1)
	}
	if processNames != "" {
		targets = append(targets, strings.Split(processNames, ",")...)
	}
	if pids != "" {
		targets = append(targets, strings.Split(pids, ",")...)
	}
	for _, t := range targets {
		if t == "0" {
			debugMode = true
			break
		}
	}
	if debugMode {
		monitorTarget = "全てのプロセス"
	} else {
		monitorTarget = strings.Join(targets, ", ")
	}
	return
}

func setupLogging(outputFile string) {
	if outputFile != "" {
		file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil { log.Fatalf("エラー: 出力ファイルを開けませんでした: %v", err) }
		log.SetOutput(io.MultiWriter(os.Stdout, file))
	}
	log.SetFlags(0)
}

func getFilteredConnections(targets []string, debugMode bool) (map[string]TCPConnection, error) {
	var size uint32
	const TCP_TABLE_OWNER_PID_ALL = 5
	ret, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
	if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("GetExtendedTcpTable (size query) failed: %d", ret)
	}
	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}
	table := (*MIB_TCPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	connections := make(map[string]TCPConnection)
	rowSize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})
	for i := uint32(0); i < table.NumEntries; i++ {
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(uintptr(unsafe.Pointer(&table.Table[0])) + uintptr(i)*rowSize))
		processName, isMatch := getProcessIfTarget(row.OwningPid, targets, debugMode)
		if isMatch {
			conn := TCPConnection{
				ProcessName: processName, PID: row.OwningPid,
				LocalAddr: ipToString(row.LocalAddr), LocalPort: portToUint16(row.LocalPort),
				RemoteAddr: ipToString(row.RemoteAddr), RemotePort: portToUint16(row.RemotePort),
				State: getTCPStateName(row.State),
			}
			if conn.RemoteAddr == "0.0.0.0" { continue }
			key := fmt.Sprintf("%s:%d -> %s:%d", conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)
			connections[key] = conn
		}
	}
	return connections, nil
}

func detectAndLogChanges(currentConns, prevConns map[string]TCPConnection) {
	timestamp := time.Now().Format("15:04:05.000")
	logHeaderPrinted := false
	printLogHeader := func() {
		if !logHeaderPrinted {
			log.Printf("--- %s 状態変化 ---", timestamp)
			logHeaderPrinted = true
		}
	}
	for key, current := range currentConns {
		prev, existed := prevConns[key]
		if !existed {
			printLogHeader()
			log.Printf("[NEW] %s | Process: %s (PID: %d) | 状態: %s", key, current.ProcessName, current.PID, current.State)
		} else if prev.State != current.State {
			printLogHeader()
			log.Printf("[CHANGE] %s | Process: %s (PID: %d) | 状態: %s -> %s", key, current.ProcessName, current.PID, prev.State, current.State)
		}
	}
	for key, prev := range prevConns {
		if _, exists := currentConns[key]; !exists {
			printLogHeader()
			log.Printf("[CLOSED] %s | Process: %s (PID: %d) | 最後の状態: %s", key, prev.ProcessName, prev.PID, prev.State)
		}
	}
}

var (
	processCache = make(map[uint32]string)
	cacheMutex   sync.Mutex
)

func getProcessIfTarget(pid uint32, targets []string, debugMode bool) (string, bool) {
	if debugMode { return getProcessName(pid), true }
	pidStr := strconv.FormatUint(uint64(pid), 10)
	for _, target := range targets {
		if target == pidStr { return getProcessName(pid), true }
	}
	processName := getProcessName(pid)
	for _, target := range targets {
		if strings.EqualFold(processName, target) { return getProcessName(pid), true }
	}
	return processName, false
}

func getProcessName(pid uint32) string {
	cacheMutex.Lock()
	name, ok := processCache[pid]
	if ok { cacheMutex.Unlock(); return name }
	cacheMutex.Unlock()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil { return "N/A" }
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err = windows.Process32First(snapshot, &entry); err != nil { return "N/A" }
	for {
		if entry.ProcessID == pid {
			processName := windows.UTF16ToString(entry.ExeFile[:])
			cacheMutex.Lock()
			processCache[pid] = processName
			cacheMutex.Unlock()
			return processName
		}
		if err = windows.Process32Next(snapshot, &entry); err != nil { break }
	}
	cacheMutex.Lock()
	processCache[pid] = "N/A"
	cacheMutex.Unlock()
	return "N/A"
}

func ipToString(ip uint32) string { return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)) }
func portToUint16(port uint32) uint16 { return uint16((port >> 8) | ((port & 0xFF) << 8)) }
func getTCPStateName(state uint32) string {
	switch state {
	case 1: return "CLOSED"; case 2: return "LISTEN"; case 3: return "SYN_SENT"; case 4: return "SYN_RECV"; case 5: return "ESTABLISHED"; case 6: return "FIN_WAIT1"; case 7: return "FIN_WAIT2"; case 8: return "CLOSE_WAIT"; case 9: return "CLOSING"; case 10: return "LAST_ACK"; case 11: return "TIME_WAIT"; case 12: return "DELETE_TCB"; default: return "UNKNOWN"
	}
}
