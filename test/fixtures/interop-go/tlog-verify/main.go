// Command tlog-verify checks EvidScope record receipts and checkpoint notes with third-party Go code, for
// test/receipts-interop.test.mjs: c2sp.org/tlog-proof@v1 with filippo.io/torchwood VerifyProof under a
// c2sp.org/tlog-policy parsed by torchwood ParsePolicy, and signed notes with golang.org/x/mod/sumdb/note.
//
//	tlog-verify proof PROOF POLICY RECORD.json      the record hash is the SHA-256 of the record file
//	tlog-verify proof-hash PROOF POLICY HASH_HEX    a record hash in hex, as listed in DSSE predicates
//	tlog-verify note NOTE LOG_VKEY [WITNESS_VKEY]... the log signature by sumdb/note, cosignatures by torchwood
//
// On success it prints a line starting with "ok" and exits 0; otherwise it exits 1.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func proof(proofPath, policyPath string, recordHash []byte) (string, error) {
	p, err := os.ReadFile(proofPath)
	if err != nil {
		return "", err
	}
	text, err := os.ReadFile(policyPath)
	if err != nil {
		return "", err
	}
	policy, err := torchwood.ParsePolicy(text)
	if err != nil {
		return "", fmt.Errorf("policy: %w", err)
	}
	if len(recordHash) != sha256.Size {
		return "", errors.New("record hash must be 32 bytes")
	}
	// The leaf is RFC 6962 SHA-256(0x00 || record hash), which is what tlog.RecordHash computes over the hash bytes.
	if err := torchwood.VerifyProof(policy, tlog.RecordHash(recordHash), p); err != nil {
		return "", err
	}
	return "ok", nil
}

func checkNote(notePath, logVkey string, witnessVkeys []string) (string, error) {
	msg, err := os.ReadFile(notePath)
	if err != nil {
		return "", err
	}
	logVerifier, err := note.NewVerifier(logVkey)
	if err != nil {
		return "", fmt.Errorf("log vkey: %w", err)
	}
	verifiers := []note.Verifier{logVerifier}
	for _, vkey := range witnessVkeys {
		v, err := torchwood.NewCosignatureVerifier(vkey)
		if err != nil {
			return "", fmt.Errorf("witness vkey: %w", err)
		}
		verifiers = append(verifiers, v)
	}
	n, err := note.Open(msg, note.VerifierList(verifiers...))
	if err != nil {
		return "", err
	}
	logSigned, cosignatures := false, 0
	for _, s := range n.Sigs {
		if s.Name == logVerifier.Name() && s.Hash == logVerifier.KeyHash() {
			logSigned = true
		} else {
			cosignatures++
		}
	}
	if !logSigned {
		return "", errors.New("the log key did not sign the note")
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return "", err
	}
	if c.Origin != logVerifier.Name() {
		return "", fmt.Errorf("checkpoint origin %q is not the log key name", c.Origin)
	}
	return fmt.Sprintf("ok %s %d %d", c.Origin, c.N, cosignatures), nil
}

func run(args []string) (string, error) {
	switch {
	case len(args) == 4 && args[0] == "proof":
		record, err := os.ReadFile(args[3])
		if err != nil {
			return "", err
		}
		h := sha256.Sum256(record)
		return proof(args[1], args[2], h[:])
	case len(args) == 4 && args[0] == "proof-hash":
		h, err := hex.DecodeString(args[3])
		if err != nil {
			return "", err
		}
		return proof(args[1], args[2], h)
	case len(args) >= 3 && args[0] == "note":
		return checkNote(args[1], args[2], args[3:])
	}
	fmt.Fprintln(os.Stderr, "usage: tlog-verify proof PROOF POLICY RECORD | proof-hash PROOF POLICY HASH_HEX | note NOTE LOG_VKEY [WITNESS_VKEY]...")
	os.Exit(2)
	return "", nil
}

func main() {
	out, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "tlog-verify:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}
