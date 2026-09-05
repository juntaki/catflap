package cli

import (
	"crypto/rand"
	"fmt"
	"strings"
)

var nameAdjectives = []string{
	"calm", "brave", "swift", "quiet", "bright", "clever", "gentle",
	"bold", "crisp", "deft", "eager", "fair", "glad", "hardy",
	"ideal", "jolly", "keen", "lively", "merry", "noble",
	"patient", "quick", "ready", "steady", "tidy", "upbeat",
	"vivid", "wise", "zesty", "amber",
}

var nameAnimals = []string{
	"panda", "fox", "crane", "otter", "heron", "badger", "ibis",
	"jay", "koala", "lark", "mole", "newt", "owl", "pika",
	"quail", "raven", "stoat", "tern", "urchin", "vole",
	"wren", "yak", "zebra", "eagle", "finch", "goose",
	"hare", "iguana", "jackal", "kite", "lemur", "marmot",
	"narwhal", "ocelot", "porpoise", "quokka", "robin", "seal",
	"turtle", "viper", "walrus",
}

// MintName returns a human-readable task name like "calm-panda".
// Callers MUST check it against live tasks and retry on collision.
func MintName() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s",
		nameAdjectives[int(b[0])%len(nameAdjectives)],
		nameAnimals[int(b[1])%len(nameAnimals)])
}

// NormalizeName lowercases and trims a name for comparison.
func NormalizeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
