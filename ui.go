package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

type progressMode int

const (
	progressAuto progressMode = iota
	progressAlways
	progressNever
)

type uiSettings struct {
	mode    progressMode
	verbose bool
	debug   bool
}

func (m progressMode) String() string {
	switch m {
	case progressAlways:
		return "always"
	case progressNever:
		return "never"
	default:
		return "auto"
	}
}

var (
	commandContext           = context.Background()
	ui                       = uiSettings{mode: progressAuto}
	uiOutput       io.Writer = os.Stderr
)

func parseGlobalUIArgs(args []string) ([]string, error) {
	for len(args) > 0 {
		switch {
		case args[0] == "--verbose" || args[0] == "-v":
			ui.verbose = true
			args = args[1:]
		case args[0] == "--debug":
			ui.debug, ui.verbose = true, true
			args = args[1:]
		case args[0] == "--no-progress":
			ui.mode = progressNever
			args = args[1:]
		case args[0] == "--progress":
			if len(args) < 2 {
				return nil, fmt.Errorf("--progress requires auto, always, or never")
			}
			if err := setProgressMode(args[1]); err != nil {
				return nil, err
			}
			args = args[2:]
		case strings.HasPrefix(args[0], "--progress="):
			if err := setProgressMode(strings.TrimPrefix(args[0], "--progress=")); err != nil {
				return nil, err
			}
			args = args[1:]
		default:
			return args, nil
		}
	}
	return args, nil
}

func setProgressMode(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto":
		ui.mode = progressAuto
	case "always":
		ui.mode = progressAlways
	case "never":
		ui.mode = progressNever
	default:
		return fmt.Errorf("invalid progress mode %q (use auto, always, or never)", value)
	}
	return nil
}

func progressTerminal() bool {
	f, ok := uiOutput.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func uiVerbosef(format string, args ...any) {
	if !ui.verbose {
		return
	}
	if progressTerminal() && ui.mode != progressNever {
		fmt.Fprint(uiOutput, "\r\033[2K")
	}
	fmt.Fprintf(uiOutput, "[sugyeol] "+format+"\n", args...)
}

func uiDebugf(format string, args ...any) {
	if !ui.debug {
		return
	}
	if progressTerminal() && ui.mode != progressNever {
		fmt.Fprint(uiOutput, "\r\033[2K")
	}
	prefix := time.Now().Format("15:04:05.000")
	fmt.Fprintf(uiOutput, "[sugyeol debug %s] "+format+"\n", append([]any{prefix}, args...)...)
}

type progressBar struct {
	mu          sync.Mutex
	label       string
	total       int64
	current     int64
	started     time.Time
	lastRender  time.Time
	lastPercent int
	terminal    bool
	disabled    bool
	closed      bool
}

func newProgress(label string, total int64) *progressBar {
	p := &progressBar{label: label, total: total, started: time.Now(), lastPercent: -1}
	p.disabled = ui.mode == progressNever
	p.terminal = progressTerminal()
	if p.disabled {
		return p
	}
	if p.terminal || ui.mode == progressAlways {
		p.render(false)
	} else {
		fmt.Fprintf(uiOutput, "[sugyeol] %s...\n", label)
	}
	if total <= 0 && (p.terminal || ui.mode == progressAlways) {
		go p.animateUnknown()
	}
	return p
}

func (p *progressBar) animateUnknown() {
	interval := 200 * time.Millisecond
	if !p.terminal {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for now := range ticker.C {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		p.renderLocked(false, now)
		p.mu.Unlock()
	}
}

func (p *progressBar) Write(b []byte) (int, error) {
	if err := commandContext.Err(); err != nil {
		return 0, err
	}
	p.Add(int64(len(b)))
	return len(b), nil
}

func (p *progressBar) Add(n int64) {
	if p == nil || n <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if p.total > 0 && n >= p.total-p.current {
		p.current = p.total
	} else {
		p.current += n
	}
	now := time.Now()
	if p.terminal {
		if now.Sub(p.lastRender) >= 100*time.Millisecond || (p.total > 0 && p.current == p.total) {
			p.renderLocked(false, now)
		}
	} else if ui.mode == progressAlways {
		percent := progressPercent(p.current, p.total)
		if percent >= p.lastPercent+10 || now.Sub(p.lastRender) >= 5*time.Second || (p.total > 0 && p.current == p.total) {
			p.renderLocked(false, now)
		}
	}
}

func (p *progressBar) SetTotal(total int64) {
	if p == nil || total <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.total = total
	p.renderLocked(false, time.Now())
}

func (p *progressBar) Finish(err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.disabled {
		return
	}
	state := tr("progress_state_done")
	if err != nil {
		state = tr("progress_state_failed")
		if errors.Is(err, context.Canceled) {
			state = tr("progress_state_canceled")
		}
	}
	if p.terminal {
		p.renderLocked(true, time.Now())
		fmt.Fprintf(uiOutput, "  %s\n", state)
		return
	}
	elapsedRaw := time.Since(p.started)
	elapsed := elapsedRaw.Round(time.Millisecond)
	rate := int64(0)
	if elapsedRaw > 0 {
		rate = int64(float64(p.current) / elapsedRaw.Seconds())
	}
	fmt.Fprint(uiOutput, "[sugyeol] "+tr("progress_summary", p.label, state, humanSize(p.current), elapsed, humanSize(rate)))
}

func (p *progressBar) render(final bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderLocked(final, time.Now())
}

func (p *progressBar) renderLocked(_ bool, now time.Time) {
	if p.disabled {
		return
	}
	p.lastRender = now
	percent := progressPercent(p.current, p.total)
	p.lastPercent = percent
	elapsed := now.Sub(p.started).Seconds()
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(p.current) / elapsed
	}
	eta := "--"
	elapsedText := now.Sub(p.started).Round(time.Second).String()
	if rate > 0 && p.total > p.current {
		eta = time.Duration(float64(p.total-p.current) / rate * float64(time.Second)).Round(time.Second).String()
	} else if p.total > 0 && p.current >= p.total {
		eta = "0s"
	}
	if p.terminal && p.total <= 0 {
		width := 24
		position := int(now.Sub(p.started)/(200*time.Millisecond)) % (2*width - 2)
		if position >= width {
			position = 2*width - 2 - position
		}
		bar := strings.Repeat(" ", position) + ">" + strings.Repeat(" ", width-position-1)
		fmt.Fprintf(uiOutput, "\r\033[2K%s [%s] working elapsed %s", p.label, bar, elapsedText)
		return
	}
	if p.terminal {
		width := 24
		filled := width * percent / 100
		if filled > width {
			filled = width
		}
		bar := strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
		line := fmt.Sprintf("\r\033[2K%s [%s] %3d%% %s/%s %s/s elapsed %s ETA %s", p.label, bar, percent, humanSize(p.current), humanSize(p.total), humanSize(int64(rate)), elapsedText, eta)
		fmt.Fprint(uiOutput, line)
		return
	}
	if ui.mode == progressAlways && p.total <= 0 {
		fmt.Fprint(uiOutput, "[sugyeol] "+tr("progress_working", p.label, now.Sub(p.started).Round(time.Second)))
	} else if ui.mode == progressAlways {
		fmt.Fprintf(uiOutput, "[sugyeol] %s: %3d%% %s/%s %s/s elapsed %s ETA %s\n", p.label, percent, humanSize(p.current), humanSize(p.total), humanSize(int64(rate)), elapsedText, eta)
	}
}

func progressPercent(current, total int64) int {
	if total <= 0 {
		return 0
	}
	p := int(float64(current) / float64(total) * 100)
	if p > 100 {
		return 100
	}
	return p
}

type progressReader struct {
	r io.Reader
	p *progressBar
}

func (r progressReader) Read(b []byte) (int, error) {
	if err := commandContext.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(b)
	if n > 0 {
		r.p.Add(int64(n))
	}
	return n, err
}

func (p *progressBar) Reader(r io.Reader) io.Reader {
	return progressReader{r: r, p: p}
}

func checkCanceled() error { return commandContext.Err() }
