package selector

const minimumVerifiedTransferBytes uint64 = 64 * 1024

// ProbeEvidence is the privacy-preserving result of one bounded, transport-specific
// connectivity probe. It intentionally contains no destination names, packet
// payloads, client addresses, or timing fingerprints.
type ProbeEvidence struct {
	Resolved                bool
	AllowedWitnessReachable bool
	EndpointReachable       bool
	HandshakeComplete       bool
	ProtectedDNSResolved    bool
	TunnelRouteConfirmed    bool
	UploadedBytes           uint64
	DownloadedBytes         uint64
}

// ClassifyProbe conservatively maps probe evidence to a retry class. A reachable
// allowlisted witness combined with an unreachable endpoint is only evidence of a
// suspected destination allowlist; it is not proof that censorship caused the
// failure. Operators must still rule out provider, routing, and firewall outages.
func ClassifyProbe(evidence ProbeEvidence) FailureClass {
	if !evidence.Resolved {
		return FailureDNS
	}
	if !evidence.EndpointReachable {
		if evidence.AllowedWitnessReachable {
			return FailureAllowlist
		}
		return FailureHandshake
	}
	if !evidence.HandshakeComplete {
		return FailureHandshake
	}
	if !evidence.ProtectedDNSResolved || !evidence.TunnelRouteConfirmed ||
		evidence.UploadedBytes < minimumVerifiedTransferBytes ||
		evidence.DownloadedBytes < minimumVerifiedTransferBytes {
		return FailureTransfer
	}
	return FailureNone
}

func ProbeHealthy(evidence ProbeEvidence) bool {
	return ClassifyProbe(evidence) == FailureNone
}
