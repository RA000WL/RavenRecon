package report

import (
	"context"
	"encoding/json"
	"fmt"
)

// renderJSON streams the complete canonical model as one JSON document:
// every dataset (already sorted by canonical identity), the statistics, the
// run and error summaries, and the model digest. Field order is the struct
// declaration order (fixed), map keys are sorted by the encoder, and no
// wall clock is read — two renders of one model produce identical bytes.
// The document is compact (machine-readable is this export's purpose; the
// human-readable forms are Markdown and HTML). HTML escaping is disabled:
// "<", ">", and "&" appear literally inside strings, as in the data itself.
func renderJSON(ctx context.Context, m *Model, s Sink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w, err := s.Writer("")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		w.Close()
		return fmt.Errorf("report: json: encode model: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("report: json: %w", err)
	}
	return nil
}
