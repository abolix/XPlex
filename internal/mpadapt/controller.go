// Package mpadapt periodically classifies pool tunnels as Active or
// Shadow based on win-rate stats from the hub.
//
// Rules (kept simple, all hysteresis-friendly):
//
//   - Always keep at least MinActive tunnels Active. Below that, every
//     live tunnel is Active no matter its score.
//   - Once we have enough Actives, demote an Active whose recent
//     win-rate is below DemoteThreshold (e.g. < 5% of frames).
//   - Promote the highest-scoring Shadow if it beats the worst Active
//     by at least PromoteMargin (e.g. shadow_wins > worst_active_wins
//     after a probe burst).
//   - Don't make more than one transition per Tick.
//   - New tunnels start Active so they get a chance to earn wins
//     before being judged.
package mpadapt

import (
	"context"
	"fmt"
	"sort"
	"time"

	"xplex/internal/mphub"
	"xplex/internal/mppool"
)

// Config controls the controller.
type Config struct {
	// MinActive is the floor on simultaneous Actives. Below this,
	// every tunnel is forced Active and no demotions happen.
	MinActive int
	// MaxActive caps how many Actives we run. 0 means "no cap" — keep
	// every healthy tunnel Active. Reasonable values for bandwidth
	// savings: 2–3.
	MaxActive int
	// Tick is the evaluation period.
	Tick time.Duration
	// DemoteThreshold: an Active whose win-rate is below this fraction
	// is a demotion candidate. e.g. 0.05 = "wins less than 5% of frames".
	DemoteThreshold float64
	// MinFrames is the number of winning frames required before any
	// classification changes happen. Avoids flipping on cold starts.
	MinFrames int64
	// CooldownAfterChange disables further changes for this duration
	// after a promotion/demotion. Prevents flapping.
	CooldownAfterChange time.Duration
}

// DefaultConfig is sensible for the project's baseline.
func DefaultConfig() Config {
	return Config{
		MinActive:           2,
		MaxActive:           2,
		Tick:                5 * time.Second,
		DemoteThreshold:     0.05,
		MinFrames:           50,
		CooldownAfterChange: 10 * time.Second,
	}
}

// Run blocks until ctx is cancelled.
func Run(ctx context.Context, hub *mphub.Hub, cfg Config) {
	if cfg.Tick == 0 {
		cfg.Tick = 5 * time.Second
	}
	if cfg.MinActive == 0 {
		cfg.MinActive = 2
	}
	if cfg.MinFrames == 0 {
		cfg.MinFrames = 50
	}
	if cfg.DemoteThreshold == 0 {
		cfg.DemoteThreshold = 0.05
	}
	if cfg.CooldownAfterChange == 0 {
		cfg.CooldownAfterChange = 10 * time.Second
	}

	t := time.NewTicker(cfg.Tick)
	defer t.Stop()
	var lastChange time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if time.Since(lastChange) < cfg.CooldownAfterChange {
				continue
			}
			if changed := evaluate(hub, cfg); changed {
				lastChange = time.Now()
			}
		}
	}
}

// evaluate runs one classification pass. Returns true if any tunnel
// changed state.
func evaluate(hub *mphub.Hub, cfg Config) bool {
	totalFrames, perTunnel := hub.WinStats()
	if totalFrames < cfg.MinFrames {
		return false // not enough data; wait
	}

	tunnels := hub.Pool().Tunnels()
	if len(tunnels) == 0 {
		return false
	}

	// Always reset stats at the end of a pass — next pass measures the
	// new configuration.
	defer hub.ResetWinStats()

	// Force minimum-active rule: if we have fewer Actives than
	// MinActive, promote the top Shadows by win count until we hit it.
	actives, shadows := splitByState(tunnels)
	if len(actives) < cfg.MinActive {
		need := cfg.MinActive - len(actives)
		if need > len(shadows) {
			need = len(shadows)
		}
		// Promote the top-scoring Shadows.
		sort.Slice(shadows, func(i, j int) bool {
			return perTunnel[shadows[i]] > perTunnel[shadows[j]]
		})
		for i := 0; i < need; i++ {
			shadows[i].SetState(mppool.StateActive)
			fmt.Printf("adapt: promote %s -> active (min-active rule)\n",
				shadows[i].Name())
		}
		return need > 0
	}

	// Honor MaxActive (if set): if we have too many Actives, demote
	// the worst-performing one each pass.
	if cfg.MaxActive > 0 && len(actives) > cfg.MaxActive {
		sort.Slice(actives, func(i, j int) bool {
			return perTunnel[actives[i]] < perTunnel[actives[j]]
		})
		demote := actives[0]
		demote.SetState(mppool.StateShadow)
		fmt.Printf("adapt: demote %s -> shadow (over MaxActive=%d, wins=%d/%d)\n",
			demote.Name(), cfg.MaxActive, perTunnel[demote], totalFrames)
		return true
	}

	// Demote rule: any Active whose win-rate is below threshold.
	worstActive := actives[0]
	worstWins := perTunnel[actives[0]]
	for _, a := range actives[1:] {
		if perTunnel[a] < worstWins {
			worstActive = a
			worstWins = perTunnel[a]
		}
	}
	worstRate := float64(worstWins) / float64(totalFrames)
	if worstRate < cfg.DemoteThreshold && len(actives) > cfg.MinActive {
		// Don't demote unless there's a Shadow that did better
		// (otherwise we'd just move the slow one around).
		bestShadow := bestShadowByWins(shadows, perTunnel)
		if bestShadow != nil && perTunnel[bestShadow] > worstWins {
			worstActive.SetState(mppool.StateShadow)
			bestShadow.SetState(mppool.StateActive)
			fmt.Printf("adapt: swap %s -> shadow (rate=%.1f%%), %s -> active (wins=%d)\n",
				worstActive.Name(), worstRate*100,
				bestShadow.Name(), perTunnel[bestShadow])
			return true
		}
	}

	return false
}

func splitByState(tunnels []*mppool.Tunnel) (actives, shadows []*mppool.Tunnel) {
	for _, t := range tunnels {
		switch t.State() {
		case mppool.StateActive:
			actives = append(actives, t)
		case mppool.StateShadow:
			shadows = append(shadows, t)
		}
	}
	return actives, shadows
}

func bestShadowByWins(shadows []*mppool.Tunnel, wins map[*mppool.Tunnel]int64) *mppool.Tunnel {
	if len(shadows) == 0 {
		return nil
	}
	var best *mppool.Tunnel
	var bestWins int64 = -1
	for _, s := range shadows {
		if w := wins[s]; w > bestWins {
			best = s
			bestWins = w
		}
	}
	return best
}

