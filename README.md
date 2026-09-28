# Library Lending Blockchain

This project extends the library book lending tracker into a blockchain-based lending system with a pending pool, reward transactions, and mining simulation. The application loads book and member registries, records borrow/return events, assigns token rewards, and then confirms pending lending records through simulated mining before the chain is updated.

## Requirements

- C11 compiler
- OpenSSL 3.x development package
- MSYS2/UCRT64 environment on Windows if using the bundled Makefile

## Build and run

From the project folder:

```sh
make CC=/ucrt64/bin/gcc
env MSYSTEM=UCRT64 MSYSTEM_PREFIX=/ucrt64 PATH=/ucrt64/bin:/usr/bin:/bin ./library_tracker.exe
```

On Linux/macOS:

```sh
make
./library_tracker
```

The first run creates the ECDSA P-256 private key in `library_private.pem`, creates the genesis block, and writes the chain to `chain.dat`.

## Switching transaction models

The program supports both transaction ledger styles through the CLI:

```text
model utxo
model account
```

- `utxo`: balances are derived from unspent outputs and fee/change handling is simulated.
- `account`: balances are stored directly per member and checked with nonce validation.

## Changing mining difficulty

Difficulty is configurable between 1 and 4 leading zero characters:

```text
set difficulty 1
set difficulty 2
set difficulty 4
```

The startup command-line option is also supported:

```sh
./library_tracker --difficulty 3 --model account
```

## Typical workflow

```text
borrow BK001 ALU001
borrow BK001 ALU002
return BK001 ALU001
pending
mine solo
view
balances
validate
```

Late returns can be marked with:

```text
return BK001 ALU001 late
```

## Mining simulation commands

```text
mine solo
mine pool
mine cloud 3
```

- `mine solo`: mines all pending records with a proof-of-work loop.
- `mine pool`: shows a reward distribution table with pool fee deduction.
- `mine cloud N`: shows a multi-round cloud mining summary for `N` rounds.

## Testing notes

Checks include:

- duplicate active loan rejection
- invalid member/book IDs
- impossible late return without active loan
- insufficient balance or invalid nonce in account mode
- chain tampering detection via `tamper`
- profitability warning for cloud mining when fees exceed rewards

## Files

- Source: [library_tracker.c](library_tracker.c)
- Design notes: [DESIGN.md](DESIGN.md)
- Technical report: [REPORT.md](REPORT.md)
- Registry: [books.txt](books.txt), [members.txt](members.txt)

## Submission checklist

- Source code is complete and compiles with the Makefile.
- Pending pool and mining flow are implemented.
- UTXO and account-based models are available.
- Documentation and testing notes are included in this README and report files.
