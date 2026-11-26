package secretscan

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func gen(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Secret-shaped fixtures are assembled at runtime so this file never contains one
// and the repository's own tenant-leak lint stays clean.
func TestM1_1_BuiltinRulesMatch(t *testing.T) {
	upper := strings.ToUpper(gen(t, 8)) // 16 chars [0-9A-F]
	alnum := strings.Repeat("aB3dE5gH7j", 4)
	cases := map[string]string{
		RuleCloudKey:       "id = " + "AK" + "IA" + upper + "\n",
		RuleForgeToken:     "export T=" + "gh" + "p_" + alnum[:36] + "\n",
		RuleChatToken:      "x" + "oxb-" + "1234567890-" + alnum[:12] + "\n",
		RulePrivateKey:     "-----" + "BEGIN RSA " + "PRIVATE KEY-----\nMII\n",
		RuleJWT:            "Authorization: Bearer " + "ey" + "J" + alnum + "." + "ey" + "J" + alnum + "." + alnum + "\n",
		RuleAssignedSecret: "api_" + "token = \"" + gen(t, 16) + "Zq/+\"\n",
	}
	for rule, text := range cases {
		fs := New(nil).Scan("f.txt", []byte(text))
		found := false
		for _, f := range fs {
			if f.Rule == rule {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %s: no finding (got %v)", rule, fs)
		}
	}
}

func TestM1_1_AssignedLowEntropyIsNotSecret(t *testing.T) {
	text := "password = \"" + strings.Repeat("a", 32) + "\"\nkey: value\n"
	if fs := New(nil).Scan("f", []byte(text)); len(fs) != 0 {
		t.Fatalf("unexpected findings: %v", fs)
	}
}

func TestM1_1_TermsMatchCaseInsensitiveAtWordBoundaries(t *testing.T) {
	term := "acme" + gen(t, 3)
	s := New([]Term{{Value: term, Rule: RuleTenantTerm}})
	text := "x\n  " + strings.ToUpper(term) + ".\nnot" + term + " " + term + "ville " + term + "_x\n(" + term + ")"
	fs := s.Scan("p", []byte(text))
	want := []Finding{{"p", 2, 3, RuleTenantTerm}, {"p", 4, 2, RuleTenantTerm}}
	if len(fs) != len(want) {
		t.Fatalf("got %v, want %v", fs, want)
	}
	for i := range want {
		if fs[i] != want[i] {
			t.Fatalf("got %v, want %v", fs, want)
		}
	}
}

func TestM1_1_BinaryIsScanned(t *testing.T) {
	term := "acme" + gen(t, 3)
	data := append([]byte{0x00, 0xff, 0xfe, '\n', 0x01}, []byte(term)...)
	data = append(data, 0x00, 0x80)
	fs := New([]Term{{Value: term, Rule: RuleTenantTerm}}).Scan("b.bin", data)
	if len(fs) != 1 || fs[0].Line != 2 || fs[0].Col != 2 {
		t.Fatalf("got %v", fs)
	}
}

func TestM1_1_FindingNeverCarriesValue(t *testing.T) {
	term := "acme" + gen(t, 3)
	fs := New([]Term{{Value: term, Rule: RuleTenantTerm}}).Scan("p", []byte(term))
	for _, f := range fs {
		if strings.Contains(strings.ToLower(f.String()), term) {
			t.Fatalf("finding echoes the term: %s", f)
		}
	}
}
