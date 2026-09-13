package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

func TestDataIntegrityLocalDialerRejectsConnectionAfterTerminalClose(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "libvirt.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("Unix socket creation is unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	dialer := &LocalDialer{SocketPath: socketPath}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}

	acceptedCh := make(chan net.Conn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		accepted, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptErrCh <- acceptErr
			return
		}
		acceptedCh <- accepted
	}()

	conn, err := dialer.Dial()
	if conn != nil {
		_ = conn.Close()
		t.Fatalf("Dial returned connection %v after terminal close", conn)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Dial error=%v, want net.ErrClosed", err)
	}

	var accepted net.Conn
	select {
	case accepted = <-acceptedCh:
		defer accepted.Close()
	case err := <-acceptErrCh:
		t.Fatalf("accept failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("listener did not observe the late connection")
	}
	if err := accepted.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := accepted.Read(one[:]); !errors.Is(err, io.EOF) {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatalf("late connection remained live until read timeout: %v", err)
		}
		t.Fatalf("server-side read error=%v, want EOF from rejected connection", err)
	}

	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if dialer.conn != nil || !dialer.closed {
		t.Fatalf("terminal dialer state conn=%v closed=%t, want nil/true", dialer.conn, dialer.closed)
	}
}

func TestDataIntegrityBlockingDomainStatsRPCTimesOutAndAbortsConnection(t *testing.T) {
	t.Parallel()

	conn := &libvirt.Libvirt{}
	local, peer := net.Pipe()
	dialer := &LocalDialer{conn: local}
	t.Cleanup(func() {
		_ = dialer.Close()
		_ = peer.Close()
	})

	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	const timeout = 30 * time.Millisecond
	mc := &MetricsCollector{
		libvirtConn:       conn,
		libvirtDialer:     dialer,
		libvirtRPCTimeout: timeout,
		im:                &InstanceManager{},
		libvirtStatsRPCOverride: func(*libvirt.Libvirt) ([]libvirt.DomainStatsRecord, error) {
			close(started)
			<-release
			close(finished)
			return nil, nil
		},
	}

	if err := peer.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	records, _, err := mc.fetchDomainStats()
	elapsed := time.Since(begin)
	if records != nil {
		t.Fatalf("records=%v, want nil after timeout", records)
	}
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error=%v, want domain stats timeout", err)
	}
	if elapsed < timeout {
		t.Fatalf("returned after %s, before configured timeout %s", elapsed, timeout)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("returned after %s, want bounded timeout", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("blocking stats override was not invoked")
	}

	mc.libvirtMu.Lock()
	gotConn := mc.libvirtConn
	gotDialer := mc.libvirtDialer
	mc.libvirtMu.Unlock()
	if gotConn != nil || gotDialer != nil {
		t.Fatalf("active libvirt connection was not aborted: conn=%p dialer=%p", gotConn, gotDialer)
	}
	dialer.mu.Lock()
	dialerConn := dialer.conn
	dialer.mu.Unlock()
	if dialerConn != nil {
		t.Fatal("active libvirt socket was not closed")
	}

	var one [1]byte
	if _, err := peer.Read(one[:]); err == nil {
		t.Fatal("peer socket remained open after abort")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("peer socket was not closed before its read deadline: %v", err)
	}

	unblock()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("stats RPC override goroutine did not exit after release")
	}
}

func TestDataIntegrityBlockingDomainXMLRPCUsesSharedDeadline(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	im := &InstanceManager{
		xmlRPCSem:         make(chan struct{}, 1),
		libvirtRPCTimeout: time.Second,
		domainXMLDescOverride: func(libvirt.Domain) (string, error) {
			close(started)
			<-release
			close(finished)
			return "", errors.New("released")
		},
	}

	const sharedBudget = 30 * time.Millisecond
	begin := time.Now()
	_, err := im.readDomainXMLDesc(libvirt.Domain{Name: "blocked-domain"}, nil, begin.Add(sharedBudget))
	elapsed := time.Since(begin)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error=%v, want domain XML timeout", err)
	}
	if elapsed < sharedBudget {
		t.Fatalf("returned after %s, before shared deadline %s", elapsed, sharedBudget)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("returned after %s, want shared deadline rather than one-second per-RPC timeout", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("blocking XML override was not invoked")
	}
	if got := len(im.xmlRPCSem); got != 1 {
		t.Fatalf("XML worker semaphore len=%d after timeout, want 1 while raw RPC is still running", got)
	}

	unblock()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("XML RPC override goroutine did not exit after release")
	}
	select {
	case im.xmlRPCSem <- struct{}{}:
		<-im.xmlRPCSem
	case <-time.After(time.Second):
		t.Fatal("XML worker semaphore was not released after the raw RPC exited")
	}
}

func TestDataIntegrityDomainXMLConcurrencyBoundsOutstandingRPCsAfterTimeout(t *testing.T) {
	t.Parallel()

	const (
		maxConcurrent = 2
		queuedCalls   = 6
	)
	started := make(chan struct{}, maxConcurrent+queuedCalls)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	im := &InstanceManager{
		xmlRPCSem:         make(chan struct{}, maxConcurrent),
		libvirtRPCTimeout: time.Second,
		domainXMLDescOverride: func(libvirt.Domain) (string, error) {
			started <- struct{}{}
			<-release
			return "", errors.New("released")
		},
	}

	type callResult struct {
		err error
	}
	results := make(chan callResult, maxConcurrent+queuedCalls)
	call := func(name string, deadline time.Time) {
		_, err := im.readDomainXMLDesc(libvirt.Domain{Name: name}, nil, deadline)
		results <- callResult{err: err}
	}

	firstDeadline := time.Now().Add(100 * time.Millisecond)
	for i := 0; i < maxConcurrent; i++ {
		go call(fmt.Sprintf("running-domain-%d", i), firstDeadline)
	}
	for i := 0; i < maxConcurrent; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("raw XML RPC did not start")
		}
	}

	queuedDeadline := time.Now().Add(30 * time.Millisecond)
	for i := 0; i < queuedCalls; i++ {
		go call(fmt.Sprintf("queued-domain-%d", i), queuedDeadline)
	}

	for i := 0; i < maxConcurrent+queuedCalls; i++ {
		select {
		case result := <-results:
			var timeoutErr *libvirtRPCTimeoutError
			if !errors.As(result.err, &timeoutErr) {
				t.Fatalf("call error=%v, want Libvirt RPC timeout", result.err)
			}
		case <-time.After(time.Second):
			t.Fatal("XML wrapper call did not honor its deadline")
		}
	}

	if got := len(started); got != 0 {
		t.Fatalf("started channel retained %d unexpected raw RPC notifications", got)
	}
	if got := len(im.xmlRPCSem); got != maxConcurrent {
		t.Fatalf("XML worker semaphore len=%d, want %d blocked raw RPCs", got, maxConcurrent)
	}

	unblock()
	releaseDeadline := time.Now().Add(time.Second)
	for len(im.xmlRPCSem) != 0 && time.Now().Before(releaseDeadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(im.xmlRPCSem); got != 0 {
		t.Fatalf("XML worker semaphore len=%d after releasing raw RPCs, want 0", got)
	}
}

func TestDataIntegrityDomainXMLTimeoutSuppressesOnlySameDomainUntilRawRPCExits(t *testing.T) {
	t.Parallel()

	blocked := libvirt.Domain{Name: "blocked-domain"}
	other := libvirt.Domain{Name: "healthy-domain"}
	blockedStarted := make(chan struct{})
	releaseBlocked := make(chan struct{})
	blockedFinished := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(releaseBlocked) }) }
	t.Cleanup(unblock)

	im := &InstanceManager{
		xmlRPCSem:            make(chan struct{}, 2),
		libvirtRPCTimeout:    time.Second,
		domainXMLRPCInflight: make(map[string]struct{}),
		domainXMLDescOverride: func(dom libvirt.Domain) (string, error) {
			if dom.Name == blocked.Name {
				select {
				case <-blockedStarted:
				default:
					close(blockedStarted)
				}
				<-releaseBlocked
				select {
				case <-blockedFinished:
				default:
					close(blockedFinished)
				}
			}
			return "<domain/>", nil
		},
	}

	_, rpcStarted, err := im.readDomainXMLDescWithRPCState(
		blocked,
		nil,
		time.Now().Add(30*time.Millisecond),
	)
	var timeoutErr *libvirtRPCTimeoutError
	if !errors.As(err, &timeoutErr) || !rpcStarted || !timeoutErr.RPCStarted {
		t.Fatalf("first blocked call result started=%v err=%v, want raw-RPC timeout", rpcStarted, err)
	}
	select {
	case <-blockedStarted:
	default:
		t.Fatal("blocked raw XML RPC did not start")
	}
	if got := len(im.xmlRPCSem); got != 1 {
		t.Fatalf("semaphore slots after blocked timeout=%d, want one", got)
	}

	_, rpcStarted, err = im.readDomainXMLDescWithRPCState(
		blocked,
		nil,
		time.Now().Add(time.Second),
	)
	if !errors.Is(err, errDomainXMLRPCAlreadyInFlight) || rpcStarted {
		t.Fatalf("same-domain retry started=%v err=%v, want in-flight rejection", rpcStarted, err)
	}
	if got := len(im.xmlRPCSem); got != 1 {
		t.Fatalf("same-domain rejection consumed a semaphore slot: %d", got)
	}

	xmlDescription, rpcStarted, err := im.readDomainXMLDescWithRPCState(
		other,
		nil,
		time.Now().Add(time.Second),
	)
	if err != nil || !rpcStarted || xmlDescription != "<domain/>" {
		t.Fatalf("other-domain call started=%v xml=%q err=%v", rpcStarted, xmlDescription, err)
	}
	if got := len(im.xmlRPCSem); got != 1 {
		t.Fatalf("other-domain completion disturbed blocked slot count: %d", got)
	}

	unblock()
	select {
	case <-blockedFinished:
	case <-time.After(time.Second):
		t.Fatal("blocked raw XML RPC did not exit after release")
	}
	deadline := time.Now().Add(time.Second)
	for {
		im.domainXMLRPCMu.Lock()
		inflight := len(im.domainXMLRPCInflight)
		im.domainXMLRPCMu.Unlock()
		if inflight == 0 && len(im.xmlRPCSem) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("raw XML RPC cleanup incomplete: inflight=%d semaphore=%d", inflight, len(im.xmlRPCSem))
		}
		time.Sleep(time.Millisecond)
	}

	xmlDescription, rpcStarted, err = im.readDomainXMLDescWithRPCState(
		blocked,
		nil,
		time.Now().Add(time.Second),
	)
	if err != nil || !rpcStarted || xmlDescription != "<domain/>" {
		t.Fatalf("post-cleanup retry started=%v xml=%q err=%v", rpcStarted, xmlDescription, err)
	}
}
