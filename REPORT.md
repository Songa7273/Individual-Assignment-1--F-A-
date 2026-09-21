# Technical Report Outline

## Introduction

This project demonstrates a blockchain-based library lending tracker. It replaces an editable single log with an append-only sequence of linked, signed lending events.

## Blockchain implementation

The application creates a genesis block and appends `BORROWED` and `RETURNED` blocks. Each block stores the registry snapshot, timestamp, previous hash, signature, and current hash. `validate` recomputes hashes and checks links.

## Security mechanisms

SHA-256 provides tamper evidence. An ECDSA P-256 private key signs the canonical transaction payload, and the corresponding public key verifies signatures when records are viewed. The private key is stored separately in `library_private.pem` and should be protected in a real deployment.

## Data persistence

The registries are loaded into arrays at startup. The chain is persisted as `chain.dat`; the signing key is persisted as a PEM file so signatures remain verifiable across restarts.

## Error handling and validation

Missing or empty registry files stop startup. Unknown book/member IDs, duplicate active loans, invalid returns, malformed registry rows, full storage, failed writes, and cryptographic failures produce explicit errors.

## Screenshots and demo evidence

Add screenshots showing startup, valid and invalid IDs, `view`, `validate`, and `tamper`. The video should narrate the same sequence in 3 to 5 minutes.

## Challenges and solutions

Discuss binary persistence, canonical payload construction, ECDSA key persistence, and testing tamper detection by modifying a historical block.
