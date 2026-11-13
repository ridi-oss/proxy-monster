package nativeapi

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"time"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NewContext freezes an ALLOW/MASK decision for a returned execution id.
func NewContext(resourceID, owner string, targetBinding []byte, decision *spi.Decision, expectedWidth *uint32, binding []byte, expiresAt time.Time) (*enginepb.NativeCachedContext, error) {
	action := relay.ParseEnfActionName(decision.Action)
	if action != pb.EnfAction_ALLOW && action != pb.EnfAction_MASK {
		return nil, ErrUnauthorized
	}
	if action == pb.EnfAction_ALLOW && len(decision.Masks) > 0 {
		return nil, ErrUnauthorized
	}
	trimmed := &pb.Verdict{Decision: action, Masks: decision.Masks, UnmaskablePermitted: decision.UnmaskablePermitted, SanitizeDiagnostics: decision.SanitizeDiagnostics, DecisionId: decision.DecisionID}
	instructions, err := proto.MarshalOptions{Deterministic: true}.Marshal(trimmed)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	record := &enginepb.NativeCachedContext{
		Version: 1, ContextId: hex.EncodeToString(nonce[:]), ResourceId: resourceID, Owner: owner,
		TargetBinding: bytes.Clone(targetBinding), ExpiresAt: timestamppb.New(expiresAt),
		ExpectedWidth: expectedWidth, RequestBinding: bytes.Clone(binding), EnforcementInstructions: instructions,
	}
	if _, err := ValidateContext(record); err != nil {
		return nil, err
	}
	return record, nil
}

// ValidateContext returns a copy of record after the checks a stored context passes.
func ValidateContext(record *enginepb.NativeCachedContext) (*enginepb.NativeCachedContext, error) {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return nil, err
	}
	return decodeContext(data)
}

// ContextVerdict decodes the trimmed enforcement instructions a cached context carries.
func ContextVerdict(record *enginepb.NativeCachedContext) (*pb.Verdict, error) {
	var verdict pb.Verdict
	if err := proto.Unmarshal(record.GetEnforcementInstructions(), &verdict); err != nil {
		return nil, ErrContextCorrupt
	}
	return &verdict, nil
}
