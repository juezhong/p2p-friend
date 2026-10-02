package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type transferLeaseState struct {
	ID    uint64
	Owner string
	Kind  string
	Path  string
	Since time.Time
}

type transferLeaseBusyError struct {
	Lease transferLeaseState
}

func (e *transferLeaseBusyError) Error() string {
	return formatTransferLeaseBusy(e.Lease, false)
}

func (s *peerSession) acquireTransferLease(kind, path string) (uint64, error) {
	kind = strings.ToUpper(strings.TrimSpace(kind))
	id := s.nextRequestID()

	if s.transferCoordinator {
		if err := s.tryAcquireTransferLease(id, "local", kind, path); err != nil {
			return 0, err
		}
		return id, nil
	}

	resp, err := s.callRPCRequest(id, rpcRequest{
		Op:           "transfer_acquire",
		Path:         path,
		LeaseID:      id,
		TransferKind: kind,
	}, 5*time.Second)
	if err != nil {
		return 0, err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "当前已有传输任务"
		}
		return 0, errors.New(resp.Error)
	}

	s.leaseMu.Lock()
	s.lease = transferLeaseState{ID: id, Owner: "local", Kind: kind, Path: path, Since: time.Now()}
	s.leaseMu.Unlock()
	return id, nil
}

func (s *peerSession) tryAcquireTransferLease(id uint64, owner, kind, path string) error {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	if s.lease.ID != 0 {
		return &transferLeaseBusyError{Lease: s.lease}
	}
	s.lease = transferLeaseState{
		ID: id, Owner: owner, Kind: strings.ToUpper(kind), Path: path, Since: time.Now(),
	}
	return nil
}

func (s *peerSession) notePassiveTransfer(kind, path string) {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	if s.lease.ID != 0 {
		return
	}
	s.lease = transferLeaseState{
		ID: ^uint64(0), Owner: "remote", Kind: strings.ToUpper(kind), Path: path, Since: time.Now(),
	}
}

func (s *peerSession) releasePassiveTransfer() {
	s.leaseMu.Lock()
	if s.lease.Owner == "remote" && s.lease.ID == ^uint64(0) {
		s.lease = transferLeaseState{}
	}
	s.leaseMu.Unlock()
}

func (s *peerSession) releaseTransferLease(id uint64) {
	if id == 0 {
		return
	}

	s.leaseMu.Lock()
	if s.lease.ID == id {
		s.lease = transferLeaseState{}
	}
	s.leaseMu.Unlock()

	if s.transferCoordinator {
		return
	}
	// Best-effort release. If the transport is closing there is nothing left to arbitrate.
	_, _ = s.callRPCRequest(s.nextRequestID(), rpcRequest{
		Op:      "transfer_release",
		LeaseID: id,
	}, 3*time.Second)
}

func (s *peerSession) releaseCoordinatorLease(id uint64) {
	s.leaseMu.Lock()
	if id == 0 || s.lease.ID == id {
		s.lease = transferLeaseState{}
	}
	s.leaseMu.Unlock()
}

func (s *peerSession) leaseSnapshot() transferLeaseState {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	return s.lease
}

func (s *peerSession) handleTransferAcquire(req rpcRequest) rpcResponse {
	if !s.transferCoordinator {
		return rpcResponse{OK: false, Error: "传输仲裁端不匹配"}
	}
	if req.LeaseID == 0 {
		return rpcResponse{OK: false, Error: "无效的传输租约"}
	}
	if err := s.tryAcquireTransferLease(req.LeaseID, "remote", req.TransferKind, req.Path); err != nil {
		var busy *transferLeaseBusyError
		if errors.As(err, &busy) {
			// 该错误要展示给 RPC 请求方，因此把仲裁端的 local/remote 视角翻转。
			return rpcResponse{OK: false, Error: formatTransferLeaseBusy(busy.Lease, true)}
		}
		return rpcResponse{OK: false, Error: err.Error()}
	}
	return rpcResponse{OK: true}
}

func (s *peerSession) handleTransferRelease(req rpcRequest) rpcResponse {
	if !s.transferCoordinator {
		return rpcResponse{OK: false, Error: "传输仲裁端不匹配"}
	}
	s.releaseCoordinatorLease(req.LeaseID)
	return rpcResponse{OK: true}
}

func formatTransferLeaseBusy(lease transferLeaseState, remoteView bool) string {
	owner := lease.Owner
	if remoteView {
		owner = invertLeaseOwner(owner)
	}
	return fmt.Sprintf("当前已有传输任务：%s %s（%s）",
		lease.Kind, displayLeasePath(lease.Path), displayLeaseOwner(owner))
}

func invertLeaseOwner(owner string) string {
	switch owner {
	case "local":
		return "remote"
	case "remote":
		return "local"
	default:
		return owner
	}
}

func displayLeaseOwner(owner string) string {
	switch owner {
	case "local":
		return "本机发起"
	case "remote":
		return "对端发起"
	default:
		return owner
	}
}

func displayLeasePath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "<未指定>"
	}
	return path
}

func (s *peerSession) setCurrentTuning(p transferTuningProfile) {
	s.tuningMu.Lock()
	s.tuning = p
	s.tuningMu.Unlock()
}

func (s *peerSession) currentTuning() transferTuningProfile {
	s.tuningMu.RLock()
	defer s.tuningMu.RUnlock()
	return s.tuning
}

func (s *peerSession) clearCurrentTuning() {
	s.tuningMu.Lock()
	s.tuning = transferTuningProfile{}
	s.tuningMu.Unlock()
}
