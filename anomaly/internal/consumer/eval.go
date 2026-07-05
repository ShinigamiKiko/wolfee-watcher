package consumer

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/wolfee-watcher/anomaly-detector/internal/baseline"
	"github.com/wolfee-watcher/anomaly-detector/internal/checker"
	"github.com/wolfee-watcher/anomaly-detector/internal/recon"
)

func (c *Consumer) evaluateRaw(ctx context.Context, data []byte) []*AnomalyEvent {
	if len(data) == 0 {
		return nil
	}
	var ev map[string]interface{}
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil
	}

	srcNS := strVal(ev, "namespace")
	srcPod := strVal(ev, "pod")
	syscall := strVal(ev, "syscall")
	if srcNS == "" || srcPod == "" || syscall == "" || ignoredNamespaces[srcNS] {
		return nil
	}

	podInfo := c.enrich.Pod(ctx, srcNS, srcPod)
	srcNode := podInfo.Node
	if srcNode == "" {
		srcNode = strVal(ev, "node")
	}
	base := &AnomalyEvent{
		Ts:            time.Now(),
		SrcNamespace:  srcNS,
		SrcDeployment: podInfo.Deployment,
		SrcPod:        srcPod,
		SrcNode:       srcNode,
		SrcProcess:    strVal(ev, "process"),
		SrcIP:         podInfo.PodIP,
		SrcContainer:  strVal(ev, "container"),
		Syscall:       syscall,
	}

	switch syscall {
	case "connect":
		return c.evalConnect(ctx, ev, base, podInfo.Labels)
	case "socket":
		return c.evalSocket(ev, base)
	case "sendto":
		return c.evalSendto(ev, base)
	case "bind":
		return c.evalBind(ev, base)
	case "accept", "accept4":
		return c.evalAccept(ev, base)
	case "ptrace":
		return []*AnomalyEvent{withDetail(base, KindProcessInjection, strVal(ev, "cmdline"))}
	case "process_vm_writev":
		return []*AnomalyEvent{withDetail(base, KindProcessInjection, "process_vm_writev — cross-process memory write")}
	case "memfd_create":
		c.recordMemfd(base.SrcNamespace, base.SrcPod, strVal(ev, "pid"))
		return nil
	case "execve", "execveat", "sched_process_exec":
		return c.evalExecve(ev, base)
	case "init_module", "finit_module":
		return []*AnomalyEvent{withDetail(base, KindKernelModuleLoad, strVal(ev, "cmdline"))}
	case "bpf":
		return []*AnomalyEvent{withDetail(base, KindEBPFLoad, strVal(ev, "cmdline"))}
	case "io_uring_setup", "io_uring_enter", "io_uring_register":
		return c.evalIOUring(base)
	case "pivot_root":
		return []*AnomalyEvent{withDetail(base, KindContainerEscape, "pivot_root — filesystem root change (container escape)")}
	case "unshare":
		return []*AnomalyEvent{withDetail(base, KindContainerEscape, "unshare — new namespace (isolation bypass)")}
	case "setns":
		return []*AnomalyEvent{withDetail(base, KindContainerEscape, "setns — joined existing namespace (possible host access)")}
	case "capset":
		return c.evalCapset(base)
	case "security_inode_rename", "security_inode_unlink",
		"security_inode_mknod", "security_inode_symlink":
		return c.evalBinaryTamper(ev, base)
	default:
		return nil
	}
}

func (c *Consumer) evalConnect(ctx context.Context, ev map[string]interface{}, base *AnomalyEvent, podLabels map[string]string) []*AnomalyEvent {
	dstIP := extractIP(ev)
	dstPort := extractPort(ev)
	if c.debugLogs {
		log.Printf("[consumer] evalConnect ns=%s pod=%s dep=%s dst=%s:%d", base.SrcNamespace, base.SrcPod, base.SrcDeployment, dstIP, dstPort)
	}
	if dstIP == "" {
		return nil
	}

	dstService, dstNS := "", ""
	if svc, ok := c.enrich.IP(ctx, dstIP); ok {
		dstService = svc.Name
		dstNS = svc.Namespace
	}

	var events []*AnomalyEvent
	policyResult, _ := c.check.Check(ctx, base.SrcNamespace, podLabels, dstIP, int(dstPort))
	if policyResult == checker.Blocked {
		events = append(events, connectEvent(base, KindPolicyBlocked, dstIP, dstPort, dstService, dstNS))
	}

	srcDepKey := base.SrcNamespace + "/" + base.SrcDeployment
	conn := baseline.ConnIndicator{
		SrcEntity: baseline.Entity{ID: srcDepKey, Type: baseline.EntityDeployment, Name: base.SrcDeployment},
		DstEntity: baseline.ExternalEntity(dstIP),
		DstPort:   dstPort,
		Protocol:  baseline.TCP,
		FlowTS:    base.Ts,
	}
	baselineResult := c.base.ProcessFlowUpdate(ctx, conn)
	if c.debugLogs {
		log.Printf("[consumer] baseline result: %v for %s → %s:%d", baselineResult, srcDepKey, dstIP, dstPort)
	}
	if baselineResult == baseline.ResultAnomaly {
		a := connectEvent(base, KindUnauthorizedFlow, dstIP, dstPort, dstService, dstNS)
		a.BaselineState = "locked"
		events = append(events, a)
	}

	for _, ra := range c.recon.Observe(base.SrcNamespace, base.SrcDeployment, dstIP, dstPort, base.Ts) {
		a := clone(base)
		a.DstIP = dstIP
		a.DstService = dstService
		a.DstNS = dstNS
		switch ra.Kind {
		case recon.KindPortScan:
			a.Kind = KindPortScan
			a.ScannedPorts = ra.Ports
			a.PortCount = ra.Count
			a.WindowSec = int(recon.ScanWindow.Seconds())
		case recon.KindSuspiciousPort:
			a.Kind = KindSuspiciousPort
			a.DstPort = dstPort
			a.PortLabel = ra.PortLabel
		}
		events = append(events, a)
	}
	return events
}

func connectEvent(base *AnomalyEvent, kind AnomalyKind, dstIP string, dstPort uint32, dstService, dstNS string) *AnomalyEvent {
	a := clone(base)
	a.Kind = kind
	a.DstIP = dstIP
	a.DstPort = dstPort
	a.DstService = dstService
	a.DstNS = dstNS
	a.Protocol = "TCP"
	return a
}

func withDetail(base *AnomalyEvent, kind AnomalyKind, detail string) *AnomalyEvent {
	a := clone(base)
	a.Kind = kind
	a.Detail = detail
	return a
}

func (c *Consumer) evalSocket(ev map[string]interface{}, base *AnomalyEvent) []*AnomalyEvent {
	args, _ := ev["args"].(map[string]interface{})
	if args == nil {
		return nil
	}
	domain, sockType := socketArgs(args)
	isNet := domain == "AF_INET" || domain == "AF_INET6" || domain == "AF_PACKET" || domain == "2" || domain == "10" || domain == "17"
	isRaw := strings.Contains(sockType, "RAW") || sockType == "3"
	if isNet && isRaw {
		a := withDetail(base, KindRawSocket, "socket("+domain+", "+sockType+")")
		return []*AnomalyEvent{a}
	}
	return nil
}

func socketArgs(args map[string]interface{}) (domain, sockType string) {
	for k, v := range args {
		switch k {
		case "domain":
			domain = stringifySocketDomain(v)
		case "type":
			sockType = stringifySocketType(v)
		}
	}
	return domain, sockType
}

func stringifySocketDomain(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		switch int(val) {
		case 2:
			return "AF_INET"
		case 10:
			return "AF_INET6"
		case 17:
			return "AF_PACKET"
		}
	}
	return ""
}

func stringifySocketType(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if int(val)&3 == 3 {
			return "SOCK_RAW"
		}
	}
	return ""
}

func (c *Consumer) evalSendto(ev map[string]interface{}, base *AnomalyEvent) []*AnomalyEvent {
	dstIP := extractIP(ev)
	dstPort := extractPort(ev)
	if dstIP == "" {
		return nil
	}
	var events []*AnomalyEvent
	for _, ra := range c.recon.Observe(base.SrcNamespace, base.SrcDeployment, dstIP, dstPort, base.Ts) {
		a := clone(base)
		a.DstIP = dstIP
		switch ra.Kind {
		case recon.KindPortScan:
			a.Kind = KindPortScan
			a.ScannedPorts = ra.Ports
			a.PortCount = ra.Count
			a.WindowSec = int(recon.ScanWindow.Seconds())
			a.Detail = "detected via sendto (raw socket)"
		case recon.KindSuspiciousPort:
			a.Kind = KindSuspiciousPort
			a.DstPort = dstPort
			a.PortLabel = ra.PortLabel
			a.Detail = "via raw socket sendto"
		}
		events = append(events, a)
	}
	return events
}

func (c *Consumer) evalBind(ev map[string]interface{}, base *AnomalyEvent) []*AnomalyEvent {
	port := extractPort(ev)
	if port == 0 {
		return nil
	}
	if label, bad := suspiciousBindPorts()[port]; bad {
		a := clone(base)
		a.Kind = KindSuspiciousBind
		a.DstIP = extractIP(ev)
		a.DstPort = port
		a.PortLabel = label
		a.Detail = "listener opened on suspicious port"
		return []*AnomalyEvent{a}
	}
	return nil
}

func suspiciousBindPorts() map[uint32]string {
	return map[uint32]string{
		4444:  "metasploit-default",
		4445:  "metasploit-alt",
		1337:  "c2-common",
		31337: "elite-c2",
		9001:  "tor",
		9050:  "tor-socks",
		6666:  "irc-c2",
		6667:  "irc",
		7777:  "c2-common",
		8888:  "c2-common",
	}
}

func (c *Consumer) evalAccept(ev map[string]interface{}, base *AnomalyEvent) []*AnomalyEvent {
	name := strings.ToLower(base.SrcDeployment + base.SrcPod)
	for _, kw := range []string{"web", "api", "server", "gateway", "nginx", "proxy", "ingress", "frontend"} {
		if strings.Contains(name, kw) {
			return nil
		}
	}
	a := clone(base)
	a.Kind = KindUnexpectedListen

	a.DstIP = extractIP(ev)
	a.DstPort = extractPort(ev)
	a.Detail = "unexpected incoming connection accepted"
	if a.DstIP != "" {
		a.Detail += " from " + a.DstIP
	}
	return []*AnomalyEvent{a}
}

func (c *Consumer) evalIOUring(base *AnomalyEvent) []*AnomalyEvent {
	detail := base.Syscall + " — io_uring async I/O (syscall-monitoring evasion vector)"
	return []*AnomalyEvent{withDetail(base, KindIOUring, detail)}
}

func (c *Consumer) evalCapset(base *AnomalyEvent) []*AnomalyEvent {
	if isContainerRuntimeInit(base.SrcProcess) {
		return nil
	}
	return []*AnomalyEvent{withDetail(base, KindPrivEscalation, "capset — capability modification (privilege escalation)")}
}

func isContainerRuntimeInit(process string) bool {
	p := strings.ToLower(strings.TrimSpace(process))
	switch {
	case p == "":
		return false
	case strings.HasPrefix(p, "runc"):
		return true
	case strings.HasPrefix(p, "crun"):
		return true
	case strings.Contains(p, "containerd-shim"):
		return true
	case strings.Contains(p, "conmon"):
		return true
	default:
		return false
	}
}

var suspiciousBinaries = map[string]struct {
	kind   AnomalyKind
	detail string
}{
	"unshare":    {KindContainerEscape, "unshare binary executed — namespace isolation bypass attempt"},
	"nsenter":    {KindContainerEscape, "nsenter binary executed — namespace entry attempt"},
	"pivot_root": {KindContainerEscape, "pivot_root binary executed — filesystem root change attempt"},
	"chroot":     {KindContainerEscape, "chroot binary executed"},
	"insmod":     {KindKernelModuleLoad, "insmod binary executed — kernel module load attempt"},
	"modprobe":   {KindKernelModuleLoad, "modprobe binary executed — kernel module load attempt"},
	"rmmod":      {KindKernelModuleLoad, "rmmod binary executed — kernel module removal attempt"},
}

func (c *Consumer) evalExecve(ev map[string]interface{}, base *AnomalyEvent) []*AnomalyEvent {
	if c.consumeRecentMemfd(base.SrcNamespace, base.SrcPod, strVal(ev, "pid")) {
		a := withDetail(base, KindFilelessExec, "memfd_create followed by execve — possible fileless malware")
		return []*AnomalyEvent{a}
	}

	for _, name := range []string{strVal(ev, "pathname"), base.SrcProcess} {
		binName := strings.ToLower(strings.TrimSpace(name))
		if i := strings.LastIndexByte(binName, '/'); i >= 0 {
			binName = binName[i+1:]
		}
		if sb, ok := suspiciousBinaries[binName]; ok {
			return []*AnomalyEvent{withDetail(base, sb.kind, sb.detail)}
		}
	}

	if bin := execBinaryPath(ev, base); bin != "" {
		if c.base.ProcessExecUpdate(base.SrcNamespace, base.SrcDeployment, bin, base.Ts) == baseline.ResultAnomaly {
			a := withDetail(base, KindUnexpectedBinary, "binary never seen during baseline window: "+bin)
			a.BaselineState = "locked"
			return []*AnomalyEvent{a}
		}
	}
	return nil
}

func execBinaryPath(ev map[string]interface{}, base *AnomalyEvent) string {
	if ep := strVal(ev, "execpath"); ep != "" && ep != "—" {
		return ep
	}
	if args, ok := ev["args"].(map[string]interface{}); ok {
		for _, k := range []string{"pathname", "cmdpath", "filepath"} {
			if p, ok := args[k].(string); ok && p != "" {
				return p
			}
		}
	}
	return base.SrcProcess
}

var systemBinaryDirs = []string{
	"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
	"/usr/local/bin/", "/usr/local/sbin/", "/usr/libexec/",
}

func isSystemBinaryPath(p string) bool {
	for _, d := range systemBinaryDirs {
		if strings.HasPrefix(p, d) && len(p) > len(d) {
			return true
		}
	}
	return false
}

func tamperTargetPaths(ev map[string]interface{}) []string {
	var paths []string
	seen := make(map[string]struct{})
	add := func(p string) {
		if !strings.HasPrefix(p, "/") {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	if args, ok := ev["args"].(map[string]interface{}); ok {
		for _, v := range args {
			if s, ok := v.(string); ok {
				add(s)
			}
		}
	}
	add(strVal(ev, "execpath"))
	for _, tok := range strings.Fields(strVal(ev, "cmdline")) {
		add(tok)
	}
	return paths
}

func tamperTargetNames(ev map[string]interface{}) []string {
	args, ok := ev["args"].(map[string]interface{})
	if !ok {
		return nil
	}
	var names []string
	for _, k := range []string{"name", "old_name", "new_name", "dentry", "old_dentry", "new_dentry", "basename"} {
		if v, ok := args[k].(string); ok && v != "" && !strings.Contains(v, "/") {
			names = append(names, v)
		}
	}
	return names
}

var systemBinaryNames = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "zsh": {}, "ash": {}, "ksh": {},
	"python": {}, "python3": {}, "perl": {}, "ruby": {}, "node": {}, "php": {}, "lua": {},
	"cat": {}, "ls": {}, "cp": {}, "mv": {}, "rm": {}, "ln": {}, "dd": {},
	"chmod": {}, "chown": {}, "chgrp": {}, "touch": {}, "mkdir": {}, "find": {},
	"grep": {}, "awk": {}, "sed": {}, "sort": {}, "head": {}, "tail": {}, "cut": {},
	"tr": {}, "xargs": {}, "tar": {}, "gzip": {}, "base64": {}, "env": {}, "echo": {},
	"id": {}, "whoami": {}, "uname": {}, "ps": {}, "top": {}, "kill": {}, "mount": {}, "umount": {},
	"sudo": {}, "su": {}, "passwd": {}, "login": {}, "chsh": {}, "chfn": {}, "newgrp": {},
	"curl": {}, "wget": {}, "nc": {}, "ncat": {}, "netcat": {}, "ss": {}, "ip": {},
	"ifconfig": {}, "netstat": {}, "ssh": {}, "scp": {}, "sftp": {}, "telnet": {}, "socat": {},
	"openssl": {}, "dpkg": {}, "apt": {}, "apt-get": {}, "apk": {}, "yum": {}, "dnf": {},
	"rpm": {}, "crontab": {}, "at": {}, "systemctl": {}, "service": {}, "busybox": {},
}

func isSystemBinaryName(name string) bool {
	_, ok := systemBinaryNames[strings.ToLower(name)]
	return ok
}

func (c *Consumer) evalBinaryTamper(ev map[string]interface{}, base *AnomalyEvent) []*AnomalyEvent {

	if paths := tamperTargetPaths(ev); len(paths) > 0 {
		for _, p := range paths {
			if isSystemBinaryPath(p) {
				detail := base.Syscall + " — system binary modified/replaced: " + p
				return []*AnomalyEvent{withDetail(base, KindBinaryTampering, detail)}
			}
		}
		return nil
	}

	for _, n := range tamperTargetNames(ev) {
		if isSystemBinaryName(n) {
			detail := base.Syscall + " — system binary modified/replaced: " + n
			return []*AnomalyEvent{withDetail(base, KindBinaryTampering, detail)}
		}
	}
	return nil
}
