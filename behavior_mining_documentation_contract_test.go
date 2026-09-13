package main

import (
	"os"
	"strings"
	"testing"
)

func TestBehaviorMiningDocumentationContract(t *testing.T) {
	content, err := os.ReadFile("BEHAVIOR_AND_MINING.md")
	if err != nil {
		t.Fatalf("read Behavior and mining contract: %v", err)
	}
	contractText := string(content)

	wantTimingTable := `| Required qualifying collections | Minimum eligible elapsed time |
| ---: | ---: |
| 2 | 15 seconds |
| 3 | 30 seconds |
| 6 | 75 seconds |`
	if !strings.Contains(contractText, wantTimingTable) {
		t.Fatal("Behavior and mining contract is missing the exact persistence timing table")
	}
	wantMiningTable := "| `high` | At least two replied flows on a dedicated endpoint | 2 collections and 15 seconds for P1/P2; otherwise 3 collections and 30 seconds | Yes |\n" +
		"| `high_persistent` | One replied flow on a dedicated endpoint | 3 collections and 30 seconds | No; CPU corroboration or the informational fallback is required |\n" +
		"| `shared` | At least three flows, at least two replied, concentrated on one shared endpoint with a limited destination set | 3 collections and 30 seconds | No; CPU corroboration is required |\n" +
		"| `shared_persistent` | One or two replied flows concentrated on one shared endpoint | 6 collections and 75 seconds | No; CPU corroboration is required |"
	if !strings.Contains(contractText, wantMiningTable) {
		t.Fatal("Behavior and mining contract is missing the exact mining evidence and persistence table")
	}

	for _, statement := range []string{
		"The supported range is 5 seconds through 1 minute, inclusive; startup rejects values outside that range.",
		"Every persistence gate requires both the configured number of consecutive complete qualifying collections and the minimum eligible elapsed time below.",
		"A failed cycle therefore cannot mature a pending candidate.",
		"Clean or changed recovery evidence clears the pending candidate and does not seed a replacement until a later complete interval.",
		"It is cleared on confirmed deletion, fixed-IP detach, known stopped or paused state, QEMU process-incarnation change, and CPU-time rollback.",
		"External rules are additive and cannot override or reprioritize a matching built-in rule.",
		"The combined `darkspace_plus_physics` kind wins over either standalone kind",
		"The combined `darkspace_plus_scan` kind wins over either standalone kind",
		"Horizontal scan; pure UDP fan-out remains a UDP protocol detection",
		"Only that transport's counts, replies, and concentration qualify it",
		"Evaluated only after every built-in class declines to match",
		"An external rule evaluates only the traffic selected by its configured port set.",
		"A scan, flood, dark-space, external, or EWMA match may select the generic kind, but it cannot suppress a valid mining candidate or lend that candidate persistence.",
		"Qualification and published labels come from one real remote-IP/port pair.",
		"A shared-port match by itself can never produce a warning or floor generic behavior severity.",
		"The old endpoint labels and active metric remain visible while the replacement pair starts its own persistence gate.",
		"The behavior transition lifecycle is the sole cooldown and change-detection authority for structured behavior events.",
		"Behavior and mining preserves the public metric identities documented in the v2.0.0 metric catalog.",
	} {
		if !strings.Contains(contractText, statement) {
			t.Fatalf("Behavior and mining contract is missing %q", statement)
		}
	}
}

func TestBehaviorMiningREADMEContract(t *testing.T) {
	content, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	readme := string(content)

	link := "[`BEHAVIOR_AND_MINING.md`](BEHAVIOR_AND_MINING.md)"
	if got := strings.Count(readme, link); got != 1 {
		t.Fatalf("README Behavior and mining contract link count=%d, want 1", got)
	}

	for _, statement := range []string{
		"Behavior persistence requires both consecutive complete qualifying collections and real eligible elapsed time.",
		"Incomplete cycles freeze behavior and mining state, while complete clean or changed evidence and exact instance-lifecycle boundaries reset it.",
		"a generic first match cannot suppress mining and a shared port alone cannot produce a warning",
		"after confirmation, the old endpoint remains visible until a replacement endpoint independently requalifies",
		"| `collection.interval` | `15s` | Background collection interval. Supported range: `5s` through `1m`, inclusive. |",
	} {
		if !strings.Contains(readme, statement) {
			t.Fatalf("README is missing Behavior and mining contract statement %q", statement)
		}
	}
}
