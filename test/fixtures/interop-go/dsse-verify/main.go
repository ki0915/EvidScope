// Command dsse-verify checks an EvidScope DSSE in-toto attestation independently of the EvidScope code, for
// test/receipts-interop.test.mjs. It uses only the Go standard library: it rebuilds the DSSE v1 pre-authentication
// encoding, verifies an Ed25519 signature with a pinned SPKI public key, checks that the keyid is the SHA-256 of that
// key's SPKI DER, and looks for the subject file's SHA-256 among the in-toto Statement v1 subjects.
//
//	dsse-verify ENVELOPE.intoto.json SUBJECT KEY.pem
//
// On success it prints "ok KEYID SUBJECT_NAME PREDICATE_TYPE" and exits 0; otherwise it exits 1.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
)

type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

type statement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// pae is the DSSE v1 pre-authentication encoding: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
func pae(payloadType string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(body)) + " ")
	b.Write(body)
	return b.Bytes()
}

// decode accepts standard and URL-safe base64, padded or not, as the DSSE protocol asks of verifiers.
func decode(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.Strict().DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func verify(envelopePath, subjectPath, keyPath string) (string, error) {
	raw, err := os.ReadFile(envelopePath)
	if err != nil {
		return "", err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("envelope: %w", err)
	}
	if env.PayloadType != "application/vnd.in-toto+json" {
		return "", fmt.Errorf("unexpected payloadType %q", env.PayloadType)
	}
	body, err := decode(env.Payload)
	if err != nil {
		return "", fmt.Errorf("payload: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", errors.New("key file is not a PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("key is not Ed25519")
	}
	fingerprint := sha256.Sum256(block.Bytes)
	keyid := hex.EncodeToString(fingerprint[:])
	message, verified := pae(env.PayloadType, body), false
	for _, s := range env.Signatures {
		sig, err := decode(s.Sig)
		if err != nil || !ed25519.Verify(key, message, sig) {
			continue
		}
		if s.KeyID != keyid {
			return "", fmt.Errorf("keyid %q is not the SHA-256 of the key's SPKI DER (%s)", s.KeyID, keyid)
		}
		verified = true
	}
	if !verified {
		return "", errors.New("no signature verifies with the pinned key")
	}
	var st statement
	if err := json.Unmarshal(body, &st); err != nil {
		return "", fmt.Errorf("statement: %w", err)
	}
	if st.Type != "https://in-toto.io/Statement/v1" || st.PredicateType == "" || len(st.Predicate) == 0 {
		return "", errors.New("payload is not an in-toto Statement v1")
	}
	subject, err := os.ReadFile(subjectPath)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(subject)
	want := hex.EncodeToString(digest[:])
	for _, s := range st.Subject {
		if s.Digest["sha256"] == want {
			return fmt.Sprintf("ok %s %s %s", keyid, s.Name, st.PredicateType), nil
		}
	}
	return "", errors.New("the subject file's SHA-256 is not a subject of the statement")
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: dsse-verify ENVELOPE.intoto.json SUBJECT KEY.pem")
		os.Exit(2)
	}
	out, err := verify(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "dsse-verify:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}
