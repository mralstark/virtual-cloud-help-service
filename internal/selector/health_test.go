package selector

import "testing"

func TestClassifyProbeRequiresFullTransferAndTunnelRoute(t *testing.T) {
	healthy := ProbeEvidence{
		Resolved: true, EndpointReachable: true, HandshakeComplete: true,
		ProtectedDNSResolved: true, TunnelRouteConfirmed: true,
		UploadedBytes: minimumVerifiedTransferBytes, DownloadedBytes: minimumVerifiedTransferBytes,
	}
	if got := ClassifyProbe(healthy); got != FailureNone {
		t.Fatalf("ClassifyProbe(healthy) = %q", got)
	}

	for name, mutate := range map[string]func(*ProbeEvidence){
		"protected DNS": func(value *ProbeEvidence) { value.ProtectedDNSResolved = false },
		"tunnel route":  func(value *ProbeEvidence) { value.TunnelRouteConfirmed = false },
		"upload":        func(value *ProbeEvidence) { value.UploadedBytes-- },
		"download":      func(value *ProbeEvidence) { value.DownloadedBytes-- },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := healthy
			mutate(&candidate)
			if got := ClassifyProbe(candidate); got != FailureTransfer {
				t.Fatalf("ClassifyProbe() = %q, want %q", got, FailureTransfer)
			}
		})
	}
}

func TestClassifyProbeTreatsAllowlistAsSuspected(t *testing.T) {
	evidence := ProbeEvidence{Resolved: true, AllowedWitnessReachable: true}
	if got := ClassifyProbe(evidence); got != FailureAllowlist {
		t.Fatalf("ClassifyProbe() = %q, want %q", got, FailureAllowlist)
	}
	if ProbeHealthy(evidence) {
		t.Fatal("ProbeHealthy() accepted suspected allowlist evidence")
	}
}

func TestClassifyProbeDoesNotInferAllowlistWithoutWitness(t *testing.T) {
	evidence := ProbeEvidence{Resolved: true}
	if got := ClassifyProbe(evidence); got != FailureHandshake {
		t.Fatalf("ClassifyProbe() = %q, want %q", got, FailureHandshake)
	}
}
