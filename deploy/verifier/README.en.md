# EvidScope offline verifier {{version}}

Checks evidence issued by an EvidScope vault **without trusting the operator, without installing EvidScope and without network
access**. It needs Node.js 24.15 or later and nothing else: no package dependencies, only the files in this folder and Node.js
built-in modules, none of which open network connections or start processes (`net`, `http`, `child_process` and the like are
not used). 한국어: [README.md](README.md)

What it checks:

| Input | Command |
|---|---|
| DSSE in-toto attestations (`*.intoto.json`) of an export bundle or a case report, with the file they name | `dsse` |
| A `c2sp.org/tlog-proof@v1` receipt of one ledger record, under a `c2sp.org/tlog-policy` | `tlog-proof` |
| The existing export bundle (`GET /api/export`) and case report (`GET /api/cases/<id>/report`) | `bundle`, `report` |
| Vault API responses (`?attest=intoto`, `/api/receipts/record`) saved as JSON, split into files | `unpack` |
| An auditor evidence package (a folder or `.tar.gz` from `scripts/evidence-pack.mjs build`) | `pack` |

Formats, URIs and what each receipt proves are described (in Korean) in
[docs/receipts.md](https://github.com/ki0915/EvidScope/blob/main/docs/receipts.md).

## 1. Check the verifier you received

Compare the SHA-256 of the archive with a value obtained over a channel other than the vault (release page, letter, ...).
After unpacking, check every file against the manifest.

```sh
sha256sum -c evidscope-verify-{{version}}.tar.gz.sha256
tar -xzf evidscope-verify-{{version}}.tar.gz && cd evidscope-verify-{{version}}
sha256sum -c SHA256SUMS
```

`SHA256SUMS` lists every file of this folder except itself. Packing the same sources again with the same Node.js version
(`node scripts/package-verifier.mjs`) gives a byte-identical archive.

## 2. Obtain the trust anchors out of band

A result means something only when these values come **from somewhere other than the vault**. A policy or key sent along by the
vault is not a trust anchor.

- The vault public key (PEM). The `keyid` of DSSE signatures is the SHA-256 of its SPKI DER:
  `openssl pkey -pubin -in vault-public.pem -outform DER | sha256sum`
- Witness keys (`--witness`, C2SP vkeys) and the quorum (`--quorum`), or a `c2sp.org/tlog-policy` file holding them
- The origin base (`--origin-base`, for example `evidscope.example.com/prod`). A tenant log origin is `<origin base>/t/<tenant hash>`.

## 3. Usage

Split saved API responses into files first. Unpacking only checks the content digest and never overwrites a file.

```sh
node evidscope-verify.mjs unpack export-response.json --out evidence/
#   evidence/evidscope-export-42.json, evidence/evidscope-export-42.json.intoto.json
node evidscope-verify.mjs unpack record-response.json --out evidence/
#   evidence/evidscope-record-<id>-17.json, .tlog-proof, .tlog-policy
```

A DSSE in-toto attestation and its subject file:

```sh
node evidscope-verify.mjs dsse evidence/evidscope-export-42.json.intoto.json evidence/evidscope-export-42.json vault-public.pem \
  --witness '<WITNESS_VKEY>' --quorum 1 --origin-base evidscope.example.com/prod --require-witnessed
```

A record receipt (with a policy file, or with key and witness flags):

```sh
node evidscope-verify.mjs tlog-proof evidence/evidscope-record-<id>-17.tlog-proof evidence/evidscope-record-<id>-17.json \
  --policy my-policy.tlog-policy --key vault-public.pem --origin-base evidscope.example.com/prod
node evidscope-verify.mjs tlog-proof R.tlog-proof R.json --key vault-public.pem --witness '<WITNESS_VKEY>' --quorum 1
```

The existing formats (`--attestation` also checks the companion attestation):

```sh
node evidscope-verify.mjs bundle export.json vault-public.pem [CHECKPOINT.json] [--attestation export.json.intoto.json] [--replay]
node evidscope-verify.mjs report report.json vault-public.pem [CHECKPOINT.json] [--attestation report.json.intoto.json]
```

An auditor evidence package ([docs/evidence-pack.md](https://github.com/ki0915/EvidScope/blob/main/docs/evidence-pack.md)): the builder's
public key comes separately from the package, like the vault key. The verifier recomputes the index and both summaries from the
verified evidence and accepts only checks it establishes itself:

```sh
node evidscope-verify.mjs pack pack-2026q3.tar.gz vault-public.pem --pack-key builder-public.pem [CHECKPOINT.json] [--tenant T]
```

Transparency flags (optional): `--witness VKEY` (repeatable) `--quorum N` `--origin-base BASE` `--max-staleness SECONDS`
`--require-transparency` `--require-tenant-witness` `--heads-key VKEY` (repeatable, the [heads signer](https://github.com/ki0915/EvidScope/blob/main/docs/signer.md)'s key)
`--require-heads-signer` (needs `--origin-base`; `vault_host` is reported only under a pinned origin base).
`node evidscope-verify.mjs help` prints the full usage.

The result is JSON on standard output. Exit status: `0` verified, `1` not verified (reason on standard error), `2` usage error.

Node.js's permission model can confine reads to this folder and the evidence folder (`unpack` also needs write access to its
output folder):

```sh
node --permission --allow-fs-read="$PWD" --allow-fs-read=/path/to/evidence evidscope-verify.mjs dsse ...
```

## 4. What is and is not proven

- `dsse`: the pinned vault key signed an in-toto Statement whose subject is the exact bytes (SHA-256) of the file; the file's own
  signatures, hash chain and checkpoint are valid; the predicate's requirement results, policy version and checkpoint reference
  equal what is recomputed from the file. Embedded tlog-proofs show the records are in a signed tenant log checkpoint, and
  `--require-witnessed` passes only when a witness quorum cosigned that checkpoint.
- `tlog-proof`: the SHA-256 of the record file (the ledger record body as signed) is included in a signed tenant log checkpoint
  that the policy's witness quorum cosigned.
- `pack`: the builder key signed an in-toto Statement naming every file of the package with its digest; the export and case
  reports inside verify as above; the index and summaries are exactly what this verifier generates from them. "Evidence present"
  is not a finding that a requirement is met, and the mapping is a draft for human review.
- Not proven: that what a record states actually happened (records are what their sources reported), records after the
  checkpoint, the export predicate's `issuedAt` (the vault's own clock), or whether a legal assessment is right. With quorum
  `none`, someone holding the vault signing key could build a diverging history that these checks alone do not reveal.

The document above also shows how to check the same files with torchwood, `golang.org/x/mod/sumdb/note` and generic DSSE tools.
