# Technical Report

## 1. Overview

This project extends the original library lending tracker into a blockchain-based lending and reward system. Borrow and return events are recorded as pending lending records; rewards are created when a return occurs; and the pending pool is only confirmed after simulated mining. The system demonstrates how blockchain transactions, reward accounting, and mining interact in a single workflow.

## 2. Lending events and reward transactions

When a member borrows a book, the system creates a pending `BORROWED` event. When the member later returns the book, a `RETURNED` record is generated with a token reward. On-time returns award 10 tokens, while late returns award 5 tokens. If the book is never returned, no reward is created. This mirrors the assignment requirement that rewards are only generated for valid returns and only after confirmation.

The pending pool stores each lending record before it is added to the chain. This separates the event from the final confirmed block, making the mining stage explicit instead of immediate.

## 3. Pending pool and mining confirmation

The system maintains a pending pool of lending records waiting for confirmation. Each record includes the book, member, action, reward, and a generated transaction ID. The `mine solo` command takes all entries in the pool and validates them through proof-of-work before adding them as confirmed blocks.

Mining uses a configurable difficulty value. The block nonce is incremented until the hash begins with the required number of leading zeros. The program prints the number of hash attempts required before the hash meets the target. Once a valid hash is found, the block is signed and appended to the chain.

## 4. UTXO implementation

The UTXO model stores all unspent outputs in memory. Each reward is treated as a transaction that credits the member, deducts a fee, and creates an additional output when applicable. A member's balance is derived by summing all unspent outputs they own.

This design supports:

- double-spend prevention by checking spent status
- fee handling with a fixed 1-coin deduction
- change output logic when an input exceeds the required output plus fee
- complete UTXO display after each confirmed block

## 5. Account-based implementation

The account-based model stores each member as an account with:

- member ID
- current token balance
- nonce
- linked-list transaction history

Each outgoing transfer checks the sender's balance and compares the provided nonce to the sender's expected value. Transfers with an invalid or reused nonce are rejected, and each valid transfer is recorded in the member's transaction history. The program exposes `history MEMBER_ID` to print the full list for a member.

## 6. Model comparison

The UTXO model is more naturally aligned with real blockchain spending because it tracks unspent outputs and rejects double spending. The account model is simpler to reason about in code and easier to audit for balances, but it requires careful nonce management to prevent replay and duplicate transactions.

Using both models within the same program demonstrates the difference between value-based and balance-based ledger semantics.

## 7. Mining simulation methodology

The mining simulation covers all required patterns:

- Solo mining: one miner validates the pending pool and receives the full reward.
- Pool mining: several simulated miners contribute hash attempts. Shares are calculated by their percentage contribution, and a 2% pool fee is deducted before distribution.
- Cloud mining: the program simulates rental rounds, deducts a fixed fee each round, and reports gross earnings, fees, and net profit with a warning if the rental becomes unprofitable.

## 8. Security and chain integrity

The chain is protected using SHA-256 hashing and ECDSA signatures. Validation recomputes each block hash, checks the previous-hash links, and verifies the digital signature for confirmed records. This makes tampering visible and shows why miners act as the trust layer before records are finalized.

## 9. Edge-case testing

The application is designed to handle and report the assignment edge cases:

- absent student generates no transaction
- insufficient balance is rejected
- failed nonce is rejected in account mode
- unprofitable cloud rental triggers a warning
- tampering breaks validation and is flagged in the demo flow

## 10. Conclusion

The system connects book lending, reward generation, pending confirmation, and mining into one working blockchain simulation. It demonstrates both the ledger mechanics and the practical role of proof-of-work mining in confirming transactions before final state updates.
