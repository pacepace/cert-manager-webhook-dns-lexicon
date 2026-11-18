package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// Keys and credentials that argparse would read as flags if passed as their
// own argument.
var awkwardValues = []string{
	"-AbCdEf0123456789_-xyz",
	"--content",
	"-",
	"--",
	"plain_Key-123",
	"a=b",
}

func optsFor(action, value string, ttl *int) lexiconCommandOptions {
	return lexiconCommandOptions{
		Provider:  "easydns",
		authUser:  value,
		authToken: value,
		action:    action,
		zone:      "illuminati.org",
		name:      "_acme-challenge.x.illuminati.org",
		content:   value,
		ttl:       ttl,
	}
}

// Every value travels inside a --flag=value argument, never on its own.
func TestLexiconArgsKeepValuesAttached(t *testing.T) {
	ttl := 600
	for _, action := range []string{"create", "delete"} {
		for _, v := range awkwardValues {
			var ttlp *int
			if action == "create" {
				ttlp = &ttl
			}
			args := lexiconArgs(optsFor(action, v, ttlp))
			want := map[string]bool{
				"--auth-username=" + v: false,
				"--auth-token=" + v:    false,
				"--content=" + v:       false,
			}
			for _, a := range args {
				if _, ok := want[a]; ok {
					want[a] = true
				}
				if a == v {
					t.Errorf("%s %q: value passed as its own argument: %q", action, v, args)
				}
			}
			for a, seen := range want {
				if !seen {
					t.Errorf("%s %q: missing %q in %q", action, v, a, args)
				}
			}
			if args[3] != action || args[4] != "illuminati.org" || args[5] != "TXT" {
				t.Errorf("%s: positionals wrong: %q", action, args)
			}
		}
	}
}

func TestLexiconArgsTTLAndPassword(t *testing.T) {
	ttl := 600
	o := optsFor("create", "k", &ttl)
	o.usePassword = true
	args := strings.Join(lexiconArgs(o), " ")
	if !strings.Contains(args, "--ttl=600") || !strings.Contains(args, "--auth-password=k") {
		t.Errorf("create args: %s", args)
	}
	if strings.Contains(strings.Join(lexiconArgs(optsFor("delete", "k", nil)), " "), "--ttl") {
		t.Error("delete without a TTL must not pass --ttl")
	}
}

// Parse the arguments with lexicon's own parser (skipped when lexicon is not
// installed; CI installs it).
const parseScript = `
import json, sys
from lexicon._private.parser import generate_cli_main_parser
a = generate_cli_main_parser().parse_args(json.loads(sys.argv[1]))
print(json.dumps({"action": a.action, "domain": a.domain, "type": a.type, "name": a.name,
                  "content": a.content, "auth_username": a.auth_username,
                  "auth_token": a.auth_token, "ttl": a.ttl}))
`

func TestLexiconParsesArgs(t *testing.T) {
	if exec.Command("python3", "-c", "import lexicon").Run() != nil {
		t.Skip("lexicon not installed")
	}
	ttl := 600
	for _, action := range []string{"create", "delete"} {
		for _, v := range awkwardValues {
			argv, _ := json.Marshal(lexiconArgs(optsFor(action, v, &ttl)))
			out, err := exec.Command("python3", "-c", parseScript, string(argv)).CombinedOutput()
			if err != nil {
				t.Fatalf("%s %q: lexicon rejected %s: %v\n%s", action, v, argv, err, out)
			}
			var got map[string]any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("%s %q: %v: %s", action, v, err, out)
			}
			if got["action"] != action || got["domain"] != "illuminati.org" || got["type"] != "TXT" ||
				got["name"] != "_acme-challenge.x.illuminati.org" || got["content"] != v ||
				got["auth_username"] != v || got["auth_token"] != v || got["ttl"] != float64(600) {
				t.Errorf("%s %q: parsed %v", action, v, got)
			}
		}
	}
}
