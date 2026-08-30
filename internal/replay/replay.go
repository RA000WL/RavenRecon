package replay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// Replay reads the JSONL file at path and replays every well-formed event
// through obs in file order. A nil obs is the off switch: it returns nil
// immediately (zero behavior change). Malformed lines are dropped and
// counted as invalid (they never reach the observer). A panicking Observer
// is contained: the event is dropped and replay continues, mirroring the
// Deriving bridge's Deriver panic containment.
func Replay(path string, obs event.Observer) error {
	if obs == nil {
		return nil
	}
	if path == "" {
		return fmt.Errorf("replay: path must not be empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("replay: open %s: %w", path, err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		trim := bytes.TrimSpace(line)
		if len(trim) == 0 {
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				break
			}
			continue
		}
		ev, uerr := unmarshalEvent(trim)
		if uerr != nil {
			// Drop malformed line, continue.
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				break
			}
			continue
		}
		safeObserve(obs, ev)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
	}
	return nil
}

// ReplayEvents reads the JSONL file and returns the decoded events in
// order. It is the test seam for byte-equal replay: the caller can feed
// the returned slice into any deterministic renderer and compare to the
// live run's rendering.
func ReplayEvents(path string) ([]event.Event, error) {
	if path == "" {
		return nil, fmt.Errorf("replay: path must not be empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("replay: open %s: %w", path, err)
	}
	defer f.Close()
	var out []event.Event
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		trim := bytes.TrimSpace(line)
		if len(trim) != 0 {
			ev, uerr := unmarshalEvent(trim)
			if uerr == nil {
				out = append(out, ev)
			}
		}
		if err != nil {
			break
		}
	}
	return out, nil
}

func safeObserve(obs event.Observer, ev event.Event) {
	if obs == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	obs.Observe(ev)
}

type envelope struct {
	Kind     string          `json:"kind"`
	Sequence uint64          `json:"sequence"`
	At       time.Time       `json:"at"`
	Severity int             `json:"severity"`
	Phase    string          `json:"phase,omitempty"`
	Category string          `json:"category,omitempty"`
	Identity string          `json:"identity,omitempty"`
	Value    string          `json:"value,omitempty"`
	Payload  json.RawMessage `json:"payload"`
}

func unmarshalEvent(data []byte) (event.Event, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return event.Event{}, err
	}
	ev := event.Event{
		Kind:     event.Kind(env.Kind),
		Sequence: env.Sequence,
		At:       env.At,
		Severity: event.Severity(env.Severity),
		Phase:    env.Phase,
		Category: env.Category,
		Identity: env.Identity,
		Value:    env.Value,
	}
	if len(env.Payload) == 0 || string(env.Payload) == "null" {
		ev.Payload = nil
		return ev, nil
	}
	switch ev.Kind {
	case event.KindScanStarted:
		var p event.ScanStarted
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindScanStopped:
		var p event.ScanStopped
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindStageStarted:
		var p event.StageStarted
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindStageFinished:
		var p event.StageFinished
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindWorkerStarted:
		var p event.WorkerStarted
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindWorkerStopped:
		var p event.WorkerStopped
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindTaskSubmitted:
		var p event.TaskSubmitted
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindTaskStarted:
		var p event.TaskStarted
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindTaskRunning:
		var p event.TaskRunning
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindTaskCompleted:
		var p event.TaskCompleted
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindTaskCancelled:
		var p event.TaskCancelled
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindTaskFailed:
		var p event.TaskFailed
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindTaskTimedOut:
		var p event.TaskTimedOut
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindCacheHit, event.KindCacheMiss:
		var p event.CacheAccess
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindAssetDiscovered:
		var p event.AssetDiscovered
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindRelationshipCreated:
		var p event.RelationshipCreated
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindEvidenceCreated:
		var p event.EvidenceCreated
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindFindingCreated:
		var p event.FindingCreated
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindRecommendationCreated:
		var p event.RecommendationCreated
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindRequestObserved:
		var p event.RequestObserved
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindRuleExecuted:
		var p event.RuleExecuted
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindWarning:
		var p event.Warning
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindError:
		var p event.Error
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindProgress:
		var p event.Progress
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindPhaseTransition:
		var p event.PhaseTransition
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindShutdown:
		var p event.Shutdown
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindRunMetadata:
		var p event.RunMetadata
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	case event.KindSummaryReady:
		if string(env.Payload) == "{}" || string(env.Payload) == "null" {
			ev.Payload = event.SummaryReady{}
			break
		}
		var p event.SummaryReady
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return event.Event{}, err
		}
		ev.Payload = p
	default:
		return event.Event{}, fmt.Errorf("replay: unknown kind %q", env.Kind)
	}
	return ev, nil
}
