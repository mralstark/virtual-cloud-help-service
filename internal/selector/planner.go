package selector

import (
	"errors"
	"sort"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

const defaultMaxCandidates = 8

type Options struct {
	UDPAvailable  bool
	MaxCandidates int
}

type Observation struct {
	ConsecutiveFailures uint16
	CooldownUntil       time.Time
	LastSuccess         time.Time
	TransferVerified    bool
}

type Candidate struct {
	NodeID   string
	Provider string
	ASN      uint32
	Endpoint manifest.Endpoint
}

type Plan struct {
	Candidates []Candidate
	RetryAt    time.Time
}

type scoredCandidate struct {
	candidate Candidate
	score     uint64
}

// Rank produces a bounded, deterministic sequence of connection attempts. It
// avoids endpoints still in cooldown and spreads adjacent attempts across
// providers and ASNs when the signed catalog makes that possible.
func Rank(document manifest.Document, observations map[string]Observation, now time.Time, options Options) (Plan, error) {
	if err := manifest.Validate(document); err != nil {
		return Plan{}, err
	}
	if options.MaxCandidates == 0 {
		options.MaxCandidates = defaultMaxCandidates
	}
	if options.MaxCandidates < 1 || options.MaxCandidates > 16 {
		return Plan{}, errors.New("selector: max candidates must be between 1 and 16")
	}

	now = now.UTC()
	active := make([]scoredCandidate, 0)
	var retryAt time.Time
	for _, node := range document.Nodes {
		for _, endpoint := range node.Endpoints {
			if endpoint.Transport == manifest.TransportAmneziaWG && !options.UDPAvailable {
				continue
			}
			observation := observations[endpoint.ID]
			if now.Before(observation.CooldownUntil) {
				if retryAt.IsZero() || observation.CooldownUntil.Before(retryAt) {
					retryAt = observation.CooldownUntil
				}
				continue
			}
			score := uint64(endpoint.Priority)*1_000 + uint64(observation.ConsecutiveFailures)*100_000
			if observation.TransferVerified && !observation.LastSuccess.IsZero() && score >= 100 {
				score -= 100
			}
			active = append(active, scoredCandidate{
				candidate: Candidate{NodeID: node.ID, Provider: node.Provider, ASN: node.ASN, Endpoint: endpoint},
				score:     score,
			})
		}
	}

	sort.Slice(active, func(i, j int) bool {
		if active[i].score == active[j].score {
			return active[i].candidate.Endpoint.ID < active[j].candidate.Endpoint.ID
		}
		return active[i].score < active[j].score
	})

	result := Plan{Candidates: make([]Candidate, 0, min(options.MaxCandidates, len(active))), RetryAt: retryAt}
	seenProviders := make(map[string]struct{})
	seenASNs := make(map[uint32]struct{})
	for len(active) > 0 && len(result.Candidates) < options.MaxCandidates {
		index := mostDiverse(active, seenProviders, seenASNs)
		selected := active[index].candidate
		result.Candidates = append(result.Candidates, selected)
		seenProviders[selected.Provider] = struct{}{}
		seenASNs[selected.ASN] = struct{}{}
		active = append(active[:index], active[index+1:]...)
	}
	return result, nil
}

func mostDiverse(candidates []scoredCandidate, seenProviders map[string]struct{}, seenASNs map[uint32]struct{}) int {
	// Diversity must not resurrect a substantially less healthy path. Failure
	// penalties are 100,000 points, while this window admits ordinary priority
	// differences only.
	maximumScore := candidates[0].score + 10_000
	for index, item := range candidates {
		if item.score > maximumScore {
			break
		}
		_, providerSeen := seenProviders[item.candidate.Provider]
		_, asnSeen := seenASNs[item.candidate.ASN]
		if !providerSeen && !asnSeen {
			return index
		}
	}
	for index, item := range candidates {
		if item.score > maximumScore {
			break
		}
		_, providerSeen := seenProviders[item.candidate.Provider]
		_, asnSeen := seenASNs[item.candidate.ASN]
		if !providerSeen || !asnSeen {
			return index
		}
	}
	return 0
}

type FailureClass string

const (
	FailureNone      FailureClass = ""
	FailureDNS       FailureClass = "dns"
	FailureHandshake FailureClass = "handshake"
	FailureTransfer  FailureClass = "transfer"
	FailureSuspected FailureClass = "suspected-censorship"
	FailureAllowlist FailureClass = "suspected-allowlist"
)

// Cooldown returns an exponential, capped delay. The caller adds up to 20 percent
// random jitter so a fleet does not retry in lockstep.
func Cooldown(class FailureClass, consecutiveFailures uint16) (time.Duration, error) {
	base, capDuration, err := cooldownBounds(class)
	if err != nil {
		return 0, err
	}
	if consecutiveFailures == 0 {
		return 0, nil
	}
	delay := base
	for count := uint16(1); count < consecutiveFailures && delay < capDuration; count++ {
		if delay > capDuration/2 {
			return capDuration, nil
		}
		delay *= 2
	}
	if delay > capDuration {
		return capDuration, nil
	}
	return delay, nil
}

func cooldownBounds(class FailureClass) (time.Duration, time.Duration, error) {
	switch class {
	case FailureDNS:
		return 5 * time.Second, 2 * time.Minute, nil
	case FailureHandshake:
		return 15 * time.Second, 10 * time.Minute, nil
	case FailureTransfer:
		return 30 * time.Second, 15 * time.Minute, nil
	case FailureSuspected:
		return 2 * time.Minute, 30 * time.Minute, nil
	case FailureAllowlist:
		return 15 * time.Minute, 6 * time.Hour, nil
	default:
		return 0, 0, errors.New("selector: unknown failure class")
	}
}
