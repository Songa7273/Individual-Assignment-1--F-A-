#include <errno.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_BOOKS 500
#define MAX_MEMBERS 500
#define MAX_BLOCKS 5000
#define MAX_PENDING 500
#define MAX_UTXOS 5000
#define HASH_HEX_LEN 65
#define SIGNATURE_MAX_LEN 72
#define BOOKS_FILE "books.txt"
#define MEMBERS_FILE "members.txt"
#define CHAIN_FILE "chain.dat"
#define KEY_FILE "library_private.pem"

#define TX_FEE 1L
#define SOLO_MINING_REWARD 50L
#define POOL_MINING_REWARD 50L
#define CLOUD_REWARD_PER_ROUND 10L
#define CLOUD_FEE_PER_ROUND 3L

typedef enum {
    MODEL_UTXO = 0,
    MODEL_ACCOUNT = 1
} TransactionModel;

typedef struct {
    char book_id[20];
    char title[80];
    char author[50];
} Book;

typedef struct {
    char member_id[20];
    char full_name[50];
    char course_code[10];
} Member;

typedef struct {
    int index;
    time_t timestamp;
    char book_id[20];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[16];
    long token_reward;
    char previous_hash[HASH_HEX_LEN];
    char transaction_id[HASH_HEX_LEN];
    unsigned long long nonce;
    unsigned char signature[SIGNATURE_MAX_LEN];
    unsigned int signature_len;
    char hash[HASH_HEX_LEN];
} Block;

typedef struct {
    int index;
    time_t timestamp;
    char book_id[20];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[16];
    long token_reward;
    char transaction_id[HASH_HEX_LEN];
} PendingLending;

typedef struct {
    char tx_id[HASH_HEX_LEN];
    char owner[20];
    long amount;
    int spent;
} UTXO;

typedef struct TxHistoryNode {
    char sender[20];
    char recipient[20];
    long amount;
    long fee;
    unsigned long nonce;
    struct TxHistoryNode *next;
} TxHistoryNode;

typedef struct {
    char member_id[20];
    long balance;
    unsigned long nonce;
    TxHistoryNode *history;
} Account;

static Book books[MAX_BOOKS];
static Member members[MAX_MEMBERS];
static Block chain[MAX_BLOCKS];
static PendingLending pending_pool[MAX_PENDING];
static UTXO utxos[MAX_UTXOS];
static Account accounts[MAX_MEMBERS];
static size_t book_count;
static size_t member_count;
static size_t chain_length;
static size_t pending_count;
static size_t utxo_count;
static int mining_difficulty = 2;
static TransactionModel current_model = MODEL_UTXO;
static EVP_PKEY *signing_key;

/* Helper utilities */
static void trim(char *text) {
    char *start = text;
    size_t length;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') {
        start++;
    }
    if (start != text) {
        memmove(text, start, strlen(start) + 1);
    }
    length = strlen(text);
    while (length > 0 && (text[length - 1] == ' ' || text[length - 1] == '\t' ||
                          text[length - 1] == '\r' || text[length - 1] == '\n')) {
        text[--length] = '\0';
    }
}

static int split_fields(char *line, char **fields, int expected) {
    int count = 0;
    char *token = strtok(line, ",");
    while (token != NULL && count < expected) {
        trim(token);
        fields[count++] = token;
        token = strtok(NULL, ",");
    }
    return count == expected;
}

static int load_books(void) {
    FILE *file = fopen(BOOKS_FILE, "r");
    char line[256];
    if (!file) {
        fprintf(stderr, "ERROR: %s is missing or cannot be opened.\n", BOOKS_FILE);
        return 0;
    }
    while (fgets(line, sizeof(line), file) && book_count < MAX_BOOKS) {
        char *fields[3];
        trim(line);
        if (line[0] == '\0') {
            continue;
        }
        if (!split_fields(line, fields, 3) || strlen(fields[0]) >= sizeof books[0].book_id ||
            strlen(fields[1]) >= sizeof books[0].title || strlen(fields[2]) >= sizeof books[0].author) {
            fprintf(stderr, "ERROR: Invalid book record in %s.\n", BOOKS_FILE);
            fclose(file);
            return 0;
        }
        strcpy(books[book_count].book_id, fields[0]);
        strcpy(books[book_count].title, fields[1]);
        strcpy(books[book_count].author, fields[2]);
        book_count++;
    }
    fclose(file);
    if (book_count == 0) {
        fprintf(stderr, "ERROR: %s is empty.\n", BOOKS_FILE);
        return 0;
    }
    return 1;
}

static int load_members(void) {
    FILE *file = fopen(MEMBERS_FILE, "r");
    char line[160];
    if (!file) {
        fprintf(stderr, "ERROR: %s is missing or cannot be opened.\n", MEMBERS_FILE);
        return 0;
    }
    while (fgets(line, sizeof(line), file) && member_count < MAX_MEMBERS) {
        char *fields[3];
        trim(line);
        if (line[0] == '\0') {
            continue;
        }
        if (!split_fields(line, fields, 3) || strlen(fields[0]) >= sizeof members[0].member_id ||
            strlen(fields[1]) >= sizeof members[0].full_name || strlen(fields[2]) >= sizeof members[0].course_code) {
            fprintf(stderr, "ERROR: Invalid member record in %s.\n", MEMBERS_FILE);
            fclose(file);
            return 0;
        }
        strcpy(members[member_count].member_id, fields[0]);
        strcpy(members[member_count].full_name, fields[1]);
        strcpy(members[member_count].course_code, fields[2]);
        member_count++;
    }
    fclose(file);
    if (member_count == 0) {
        fprintf(stderr, "ERROR: %s is empty.\n", MEMBERS_FILE);
        return 0;
    }
    return 1;
}

static const Book *find_book(const char *id) {
    for (size_t i = 0; i < book_count; i++) {
        if (strcmp(books[i].book_id, id) == 0) {
            return &books[i];
        }
    }
    return NULL;
}

static const Member *find_member(const char *id) {
    for (size_t i = 0; i < member_count; i++) {
        if (strcmp(members[i].member_id, id) == 0) {
            return &members[i];
        }
    }
    return NULL;
}

static Account *find_account(const char *member_id) {
    for (size_t i = 0; i < member_count; i++) {
        if (strcmp(accounts[i].member_id, member_id) == 0) {
            return &accounts[i];
        }
    }
    return NULL;
}

static void sha256_hex(const char *data, size_t length, char output[HASH_HEX_LEN]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(context, data, length) != 1 ||
        EVP_DigestFinal_ex(context, digest, &digest_length) != 1) {
        fprintf(stderr, "ERROR: SHA-256 operation failed.\n");
        EVP_MD_CTX_free(context);
        exit(EXIT_FAILURE);
    }
    for (unsigned int i = 0; i < digest_length; i++) {
        snprintf(output + (i * 2), HASH_HEX_LEN - (i * 2), "%02x", digest[i]);
    }
    output[digest_length * 2] = '\0';
    EVP_MD_CTX_free(context);
}

static void generate_transaction_id(const char *book_id, const char *member_id,
                                   const char *action, long reward, char output[HASH_HEX_LEN]) {
    char payload[256];
    snprintf(payload, sizeof(payload), "%s|%s|%s|%ld|%lld", book_id, member_id, action,
             reward, (long long)time(NULL));
    sha256_hex(payload, strlen(payload), output);
}

static void block_payload(const Block *block, char *payload, size_t capacity) {
    snprintf(payload, capacity,
             "%d|%lld|%s|%s|%s|%s|%s|%ld|%s|%llu|%s",
             block->index,
             (long long)block->timestamp,
             block->book_id,
             block->book_title,
             block->member_id,
             block->member_name,
             block->action,
             block->token_reward,
             block->transaction_id,
             block->nonce,
             block->previous_hash);
}

static void calculate_hash(Block *block) {
    char payload[512];
    block_payload(block, payload, sizeof(payload));
    sha256_hex(payload, strlen(payload), block->hash);
}

static int hash_matches_difficulty(const char *hash, int difficulty) {
    if (difficulty <= 0) {
        return 1;
    }
    for (int i = 0; i < difficulty; i++) {
        if (hash[i] != '0') {
            return 0;
        }
    }
    return 1;
}

static int sign_block(Block *block) {
    char payload[512];
    size_t signature_length = sizeof block->signature;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    block_payload(block, payload, sizeof payload);
    if (!context || EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, signing_key) != 1 ||
        EVP_DigestSignUpdate(context, payload, strlen(payload)) != 1 ||
        EVP_DigestSignFinal(context, block->signature, &signature_length) != 1) {
        EVP_MD_CTX_free(context);
        return 0;
    }
    block->signature_len = (unsigned int)signature_length;
    EVP_MD_CTX_free(context);
    return 1;
}

static int verify_signature(const Block *block) {
    char payload[512];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    block_payload(block, payload, sizeof payload);
    if (!context || EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, signing_key) != 1 ||
        EVP_DigestVerifyUpdate(context, payload, strlen(payload)) != 1) {
        EVP_MD_CTX_free(context);
        return 0;
    }
    int valid = EVP_DigestVerifyFinal(context, block->signature, block->signature_len) == 1;
    EVP_MD_CTX_free(context);
    return valid;
}

static int load_or_create_key(void) {
    FILE *file = fopen(KEY_FILE, "rb");
    if (file) {
        signing_key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
        fclose(file);
        if (!signing_key) {
            fprintf(stderr, "ERROR: Could not read %s.\n", KEY_FILE);
            return 0;
        }
        return 1;
    }

    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!context || EVP_PKEY_keygen_init(context) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_keygen(context, &signing_key) != 1) {
        fprintf(stderr, "ERROR: Could not generate ECDSA key.\n");
        EVP_PKEY_CTX_free(context);
        return 0;
    }
    EVP_PKEY_CTX_free(context);
    file = fopen(KEY_FILE, "wb");
    if (!file || PEM_write_PrivateKey(file, signing_key, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "ERROR: Could not save %s.\n", KEY_FILE);
        if (file) {
            fclose(file);
        }
        return 0;
    }
    fclose(file);
    return 1;
}

static void make_genesis(void) {
    memset(&chain[0], 0, sizeof(chain[0]));
    chain[0].index = 0;
    chain[0].timestamp = time(NULL);
    strcpy(chain[0].action, "GENESIS");
    strcpy(chain[0].member_name, "Blockchain genesis");
    memset(chain[0].previous_hash, '0', 64);
    chain[0].previous_hash[64] = '\0';
    chain[0].nonce = 0;
    chain[0].token_reward = 0;
    calculate_hash(&chain[0]);
    chain_length = 1;
}

static int save_chain(void) {
    FILE *file = fopen(CHAIN_FILE, "wb");
    if (!file) {
        fprintf(stderr, "ERROR: Cannot save %s: %s\n", CHAIN_FILE, strerror(errno));
        return 0;
    }
    int result = fwrite(chain, sizeof(Block), chain_length, file) == (size_t)chain_length;
    fclose(file);
    return result;
}

static int load_chain(void) {
    FILE *file = fopen(CHAIN_FILE, "rb");
    if (!file) {
        make_genesis();
        return save_chain();
    }
    chain_length = fread(chain, sizeof(Block), MAX_BLOCKS, file);
    fclose(file);
    if (chain_length == 0 || chain[0].index != 0) {
        fprintf(stderr, "ERROR: Chain storage is invalid.\n");
        return 0;
    }
    return 1;
}

static void init_accounts(void) {
    for (size_t i = 0; i < member_count; i++) {
        memset(&accounts[i], 0, sizeof(accounts[i]));
        strcpy(accounts[i].member_id, members[i].member_id);
        accounts[i].balance = 0;
        accounts[i].nonce = 0;
        accounts[i].history = NULL;
    }
}

static void add_utxo(const char *owner, const char *tx_id, long amount) {
    if (utxo_count >= MAX_UTXOS) {
        fprintf(stderr, "ERROR: UTXO pool is full.\n");
        return;
    }
    strcpy(utxos[utxo_count].tx_id, tx_id);
    strcpy(utxos[utxo_count].owner, owner);
    utxos[utxo_count].amount = amount;
    utxos[utxo_count].spent = 0;
    utxo_count++;
}

static long long get_utxo_balance(const char *member_id) {
    long long total = 0;
    for (size_t i = 0; i < utxo_count; i++) {
        if (!utxos[i].spent && strcmp(utxos[i].owner, member_id) == 0) {
            total += utxos[i].amount;
        }
    }
    return total;
}

static int create_utxo_reward(const char *member_id, long reward) {
    static const char system_owner[] = "SYSTEM";
    char tx_id[HASH_HEX_LEN];
    char change_id[HASH_HEX_LEN];
    long fee = TX_FEE;
    long net_amount = reward - fee;
    if (reward <= 0 || net_amount <= 0) {
        printf("ERROR: Reward is too small to process.\n");
        return 0;
    }
    generate_transaction_id(member_id, system_owner, "REWARD", reward, tx_id);
    generate_transaction_id("SYSTEM", member_id, "FEE", fee, change_id);
    add_utxo(member_id, tx_id, net_amount);
    add_utxo(system_owner, change_id, fee);
    printf("UTXO reward credited to %s: gross=%ld, fee=%ld, net=%ld\n", member_id, reward, fee, net_amount);
    return 1;
}

static void print_utxo_set(void) {
    printf("\nUTXO set:\n");
    if (utxo_count == 0) {
        printf("  No UTXOs available.\n");
        return;
    }
    for (size_t i = 0; i < utxo_count; i++) {
        if (!utxos[i].spent) {
            printf("  [%zu] owner=%s amount=%ld tx=%s\n", i, utxos[i].owner, utxos[i].amount, utxos[i].tx_id);
        }
    }
}

static long long get_account_balance(const char *member_id) {
    Account *account = find_account(member_id);
    return account ? account->balance : 0;
}

static void prepend_history(Account *account, const char *sender, const char *recipient,
                           long amount, long fee, unsigned long nonce) {
    TxHistoryNode *node = malloc(sizeof(*node));
    if (!node) {
        fprintf(stderr, "ERROR: Memory allocation failed while recording history.\n");
        return;
    }
    snprintf(node->sender, sizeof(node->sender), "%s", sender);
    snprintf(node->recipient, sizeof(node->recipient), "%s", recipient);
    node->amount = amount;
    node->fee = fee;
    node->nonce = nonce;
    node->next = account->history;
    account->history = node;
}

static void print_member_history(const char *member_id) {
    Account *account = find_account(member_id);
    if (!account) {
        printf("ERROR: Unknown member ID %s.\n", member_id);
        return;
    }
    printf("\nTransaction history for %s:\n", member_id);
    if (!account->history) {
        printf("  No transactions recorded.\n");
        return;
    }
    for (TxHistoryNode *node = account->history; node != NULL; node = node->next) {
        printf("  sender=%s recipient=%s amount=%ld fee=%ld nonce=%lu\n",
               node->sender, node->recipient, node->amount, node->fee, node->nonce);
    }
}

static void print_account_balances(void) {
    printf("\nAccount balances:\n");
    for (size_t i = 0; i < member_count; i++) {
        printf("  %s: %lld\n", accounts[i].member_id, get_account_balance(accounts[i].member_id));
    }
}

static int process_account_reward(const char *member_id, long reward) {
    Account *account = find_account(member_id);
    if (!account) {
        return 0;
    }
    account->balance += reward;
    prepend_history(account, "LIBRARY", member_id, reward, 0L, account->nonce++);
    return 1;
}

static int submit_account_transfer(const char *sender, const char *recipient,
                                  long amount, long fee, unsigned long nonce) {
    Account *sender_account = find_account(sender);
    Account *recipient_account = find_account(recipient);
    if (!sender_account || !recipient_account) {
        printf("ERROR: Sender or recipient is unknown.\n");
        return 0;
    }
    if (sender_account->nonce != nonce) {
        printf("ERROR: Invalid nonce for %s. Expected %lu but received %lu.\n",
               sender, sender_account->nonce, nonce);
        return 0;
    }
    if (sender_account->balance < amount + fee) {
        printf("ERROR: Insufficient balance for %s.\n", sender);
        return 0;
    }
    sender_account->balance -= amount + fee;
    recipient_account->balance += amount;
    sender_account->nonce++;
    prepend_history(sender_account, sender, recipient, amount, fee, nonce);
    prepend_history(recipient_account, sender, recipient, amount, fee, nonce);
    printf("Transfer approved: %s -> %s amount=%ld fee=%ld nonce=%lu\n",
           sender, recipient, amount, fee, nonce);
    return 1;
}

/* Pending pool and mining */
static int book_is_on_loan(const char *book_id) {
    for (size_t i = 0; i < pending_count; i++) {
        if (strcmp(pending_pool[i].book_id, book_id) == 0) {
            return 1;
        }
    }
    for (size_t i = 1; i < chain_length; i++) {
        if (strcmp(chain[i].book_id, book_id) == 0 && strcmp(chain[i].action, "BORROWED") == 0) {
            int seen_return = 0;
            for (size_t j = i + 1; j < chain_length; j++) {
                if (strcmp(chain[j].book_id, book_id) == 0 && strcmp(chain[j].action, "RETURNED") == 0) {
                    seen_return = 1;
                    break;
                }
            }
            if (!seen_return) {
                return 1;
            }
        }
    }
    return 0;
}

static void add_pending_block(const Book *book, const Member *member, const char *action,
                              long reward, bool late_return) {
    PendingLending *entry;
    if (pending_count >= MAX_PENDING) {
        fprintf(stderr, "ERROR: Pending pool is full.\n");
        return;
    }
    entry = &pending_pool[pending_count];
    memset(entry, 0, sizeof(*entry));
    entry->index = (int)pending_count;
    entry->timestamp = time(NULL);
    strcpy(entry->book_id, book->book_id);
    strcpy(entry->book_title, book->title);
    strcpy(entry->member_id, member->member_id);
    strcpy(entry->member_name, member->full_name);
    snprintf(entry->action, sizeof(entry->action), "%s", action);
    entry->token_reward = reward;
    generate_transaction_id(book->book_id, member->member_id, action, reward, entry->transaction_id);
    pending_count++;
    printf("Pending %s for book %s by %s. Reward=%ld (late=%s)\n",
           action, book->book_id, member->member_id, reward, late_return ? "yes" : "no");
}

static void borrow_book(const char *book_id, const char *member_id) {
    const Book *book = find_book(book_id);
    const Member *member = find_member(member_id);
    if (!book || !member) {
        printf("ERROR: Book or member not found.\n");
        return;
    }
    if (book_is_on_loan(book_id)) {
        printf("ERROR: Book is already on loan.\n");
        return;
    }
    add_pending_block(book, member, "BORROWED", 0L, false);
}

static void return_book(const char *book_id, const char *member_id, bool late_return) {
    const Book *book = find_book(book_id);
    const Member *member = find_member(member_id);
    if (!book || !member) {
        printf("ERROR: Book or member not found.\n");
        return;
    }
    if (!book_is_on_loan(book_id)) {
        printf("ERROR: Book has no active loan.\n");
        return;
    }
    add_pending_block(book, member, "RETURNED", late_return ? 5L : 10L, late_return);
}

static void show_pending_pool(void) {
    printf("\nPending pool status:\n");
    if (pending_count == 0) {
        printf("  No unconfirmed lending blocks are waiting to be mined.\n");
        return;
    }
    for (size_t i = 0; i < pending_count; i++) {
        PendingLending *entry = &pending_pool[i];
        printf("  [%zu] book=%s title=%s member=%s action=%s reward=%ld tx=%s\n",
               i, entry->book_id, entry->book_title, entry->member_id, entry->action,
               entry->token_reward, entry->transaction_id);
    }
}

static void append_confirmed_block(const PendingLending *entry) {
    Block *block;
    if (chain_length >= MAX_BLOCKS) {
        fprintf(stderr, "ERROR: Chain storage is full.\n");
        return;
    }
    block = &chain[chain_length];
    memset(block, 0, sizeof(*block));
    block->index = (int)chain_length;
    block->timestamp = entry->timestamp;
    strcpy(block->book_id, entry->book_id);
    strcpy(block->book_title, entry->book_title);
    strcpy(block->member_id, entry->member_id);
    strcpy(block->member_name, entry->member_name);
    snprintf(block->action, sizeof(block->action), "%s", entry->action);
    block->token_reward = entry->token_reward;
    strcpy(block->transaction_id, entry->transaction_id);
    strcpy(block->previous_hash, chain[chain_length - 1].hash);
    block->nonce = 0;
    calculate_hash(block);

    while (!hash_matches_difficulty(block->hash, mining_difficulty)) {
        block->nonce++;
        calculate_hash(block);
    }

    if (!sign_block(block)) {
        fprintf(stderr, "ERROR: Could not sign confirmed block.\n");
        return;
    }
    printf("Mining confirmed block %d with %llu hash attempts; hash=%s\n",
           block->index, block->nonce, block->hash);

    if (strcmp(block->action, "RETURNED") == 0 && block->token_reward > 0) {
        if (current_model == MODEL_UTXO) {
            create_utxo_reward(block->member_id, block->token_reward);
        } else {
            process_account_reward(block->member_id, block->token_reward);
        }
    }

    chain_length++;
    if (!save_chain()) {
        fprintf(stderr, "ERROR: Failed to persist the mined block.\n");
    }
}

static void mine_pending_pool(void) {
    while (pending_count > 0) {
        PendingLending current = pending_pool[0];
        memmove(&pending_pool[0], &pending_pool[1], sizeof(PendingLending) * (pending_count - 1));
        pending_count--;
        append_confirmed_block(&current);
    }
    printf("All pending lending records were mined and confirmed.\n");
}

static void mine_pool_sharing(void) {
    const int miner_count = 4;
    int attempts[miner_count];
    long reward_total = 0;
    int total_attempts = 0;
    printf("\nPool mining reward distribution (2%% fee deducted):\n");
    printf("%-8s %-12s %-14s %-12s\n", "Miner", "Attempts", "Share %", "Reward");
    for (int i = 0; i < miner_count; i++) {
        attempts[i] = 20 + (rand() % 80);
        total_attempts += attempts[i];
    }
    long net_pool_reward = (long)((double)POOL_MINING_REWARD * 0.98);
    for (int i = 0; i < miner_count; i++) {
        double share = (double)attempts[i] / (double)total_attempts * 100.0;
        long miner_reward = (long)((double)attempts[i] / (double)total_attempts * net_pool_reward);
        reward_total += miner_reward;
        printf("%-8d %-12d %-14.2f %-12ld\n", i + 1, attempts[i], share, miner_reward);
    }
    printf("Pool fees deducted: %ld\n", POOL_MINING_REWARD - net_pool_reward);
    printf("Total pool rewards distributed: %ld\n", reward_total);
}

static void mine_cloud_rental(int rounds) {
    long gross_earnings = 0;
    long fees_paid = 0;
    long cumulative_rewards = 0;
    long cumulative_fees = 0;
    printf("\nCloud mining rental summary (%d rounds):\n", rounds);
    printf("%-8s %-12s %-12s %-12s %-12s\n", "Round", "Reward", "Fee", "Net", "Cumulative");
    for (int round = 1; round <= rounds; round++) {
        long reward = CLOUD_REWARD_PER_ROUND;
        long fee = CLOUD_FEE_PER_ROUND;
        long net = reward - fee;
        gross_earnings += reward;
        fees_paid += fee;
        cumulative_rewards += reward;
        cumulative_fees += fee;
        printf("%-8d %-12ld %-12ld %-12ld %-12ld\n", round, reward, fee, net, cumulative_rewards - cumulative_fees);
        if (cumulative_fees > cumulative_rewards) {
            printf("WARNING: Cloud rental is unprofitable at round %d.\n", round);
        }
    }
    printf("Gross earnings: %ld\n", gross_earnings);
    printf("Total fees paid: %ld\n", fees_paid);
    printf("Net profit: %ld\n", gross_earnings - fees_paid);
}

static int validate_chain(void) {
    int valid = 1;
    for (size_t i = 0; i < chain_length; i++) {
        char expected_hash[HASH_HEX_LEN];
        Block copy = chain[i];
        strcpy(expected_hash, copy.hash);
        calculate_hash(&copy);
        if (strcmp(expected_hash, copy.hash) != 0) {
            printf("INVALID: Block %d has an incorrect hash.\n", chain[i].index);
            valid = 0;
        }
        if (i > 0 && strcmp(chain[i].previous_hash, chain[i - 1].hash) != 0) {
            printf("INVALID: Block %d has a broken previous-hash link.\n", chain[i].index);
            valid = 0;
        }
        if (chain[i].signature_len > 0 && !verify_signature(&chain[i])) {
            printf("INVALID: Block %d has a broken signature.\n", chain[i].index);
            valid = 0;
        }
    }
    if (valid) {
        printf("VALID: Chain integrity and hash links verified (%zu blocks).\n", chain_length);
    }
    return valid;
}

static void view_records(void) {
    printf("\nConfirmed records:\n");
    if (chain_length <= 1) {
        printf("  No lending records yet.\n");
        return;
    }
    for (size_t i = 1; i < chain_length; i++) {
        char time_text[32];
        struct tm *time_info = localtime(&chain[i].timestamp);
        strftime(time_text, sizeof(time_text), "%Y-%m-%d %H:%M:%S", time_info);
        printf("\nBlock %d | %s\n  Book: %s (%s)\n  Member: %s (%s)\n  Action: %s\n  Token reward: %ld\n  TxID: %s\n  Signature: %s\n",
               chain[i].index, time_text,
               chain[i].book_title, chain[i].book_id,
               chain[i].member_name, chain[i].member_id,
               chain[i].action, chain[i].token_reward, chain[i].transaction_id,
               verify_signature(&chain[i]) ? "VALID" : "INVALID");
    }
}

static void demonstrate_tamper(void) {
    if (chain_length < 2) {
        printf("ERROR: Record at least one transaction before demonstrating tamper detection.\n");
        return;
    }
    printf("Before tampering: ");
    validate_chain();
    chain[1].book_title[0] = chain[1].book_title[0] == 'X' ? 'T' : 'X';
    printf("After modifying block 1: ");
    validate_chain();
    printf("The tampered chain remains in memory only; restart to reload the persisted chain.\n");
    load_chain();
}

static void print_model_status(void) {
    const char *label = current_model == MODEL_UTXO ? "UTXO" : "Account-based";
    printf("Current transaction model: %s\n", label);
    printf("Mining difficulty: %d leading zero character(s)\n", mining_difficulty);
}

static void print_help(void) {
    printf("\nCommands:\n");
    printf("  borrow BOOK_ID MEMBER_ID\n");
    printf("  return BOOK_ID MEMBER_ID [late]\n");
    printf("  pending\n");
    printf("  view\n");
    printf("  validate\n");
    printf("  balances\n");
    printf("  utxos\n");
    printf("  history MEMBER_ID\n");
    printf("  transfer SENDER RECIPIENT AMOUNT FEE NONCE\n");
    printf("  mine solo\n");
    printf("  mine pool\n");
    printf("  mine cloud ROUNDS\n");
    printf("  model utxo\n");
    printf("  model account\n");
    printf("  set difficulty N (1-4)\n");
    printf("  tamper\n");
    printf("  help\n");
    printf("  exit\n");
}

static void apply_cli_model(const char *mode) {
    if (strcmp(mode, "utxo") == 0) {
        current_model = MODEL_UTXO;
    } else if (strcmp(mode, "account") == 0) {
        current_model = MODEL_ACCOUNT;
    } else {
        printf("ERROR: Unknown model %s. Use utxo or account.\n", mode);
    }
    print_model_status();
}

static void parse_cli_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            apply_cli_model(argv[++i]);
        } else if (strcmp(argv[i], "--difficulty") == 0 && i + 1 < argc) {
            char *end = NULL;
            long value = strtol(argv[++i], &end, 10);
            if (end == argv[i] || value < 1 || value > 4) {
                printf("ERROR: Difficulty must be an integer from 1 to 4.\n");
            } else {
                mining_difficulty = (int)value;
            }
        }
    }
}

int main(int argc, char **argv) {
    char line[200];
    char command[32];
    char first[40];
    char second[40];
    char third[40];
    char fourth[40];
    char fifth[40];
    OpenSSL_add_all_algorithms();
    parse_cli_args(argc, argv);
    if (!load_books() || !load_members() || !load_or_create_key() || !load_chain()) {
        return EXIT_FAILURE;
    }
    init_accounts();
    if (utxo_count == 0) {
        add_utxo("SYSTEM", "GENESIS_UTXO", 100000L);
    }
    printf("Library Lending Blockchain\nLoaded %zu books and %zu members.\n", book_count, member_count);
    print_model_status();
    print_help();

    while (printf("\n> ") && fgets(line, sizeof line, stdin)) {
        int fields = sscanf(line, "%31s %39s %39s %39s %39s %39s", command, first, second, third, fourth, fifth);
        trim(command);
        if (fields == 1 && strcmp(command, "view") == 0) {
            view_records();
        } else if (fields == 1 && strcmp(command, "pending") == 0) {
            show_pending_pool();
        } else if (fields == 1 && strcmp(command, "validate") == 0) {
            validate_chain();
        } else if (fields == 1 && strcmp(command, "balances") == 0) {
            if (current_model == MODEL_UTXO) {
                for (size_t i = 0; i < member_count; i++) {
                    printf("  %s: %lld\n", members[i].member_id, get_utxo_balance(members[i].member_id));
                }
                print_utxo_set();
            } else {
                print_account_balances();
            }
        } else if (fields == 1 && strcmp(command, "help") == 0) {
            print_help();
        } else if (fields == 1 && strcmp(command, "exit") == 0) {
            break;
        } else if (fields == 1 && strcmp(command, "tamper") == 0) {
            demonstrate_tamper();
        } else if (fields == 1 && strcmp(command, "mine") == 0) {
            printf("ERROR: Use 'mine solo', 'mine pool', or 'mine cloud ROUNDS'.\n");
        } else if (fields == 2 && strcmp(command, "mine") == 0 && strcmp(first, "solo") == 0) {
            if (pending_count == 0) {
                printf("ERROR: No pending lending blocks to mine.\n");
            } else {
                mine_pending_pool();
            }
        } else if (fields == 2 && strcmp(command, "mine") == 0 && strcmp(first, "pool") == 0) {
            mine_pool_sharing();
        } else if (fields == 3 && strcmp(command, "mine") == 0 && strcmp(first, "cloud") == 0) {
            char *end = NULL;
            long rounds = strtol(second, &end, 10);
            if (end == second || rounds < 1 || rounds > 5) {
                printf("ERROR: Cloud mining rounds must be between 1 and 5.\n");
            } else {
                mine_cloud_rental((int)rounds);
            }
        } else if (fields == 2 && strcmp(command, "model") == 0) {
            apply_cli_model(first);
        } else if (fields == 3 && strcmp(command, "set") == 0 && strcmp(first, "difficulty") == 0) {
            char *end = NULL;
            long value = strtol(second, &end, 10);
            if (end == second || value < 1 || value > 4) {
                printf("ERROR: Difficulty must be between 1 and 4.\n");
            } else {
                mining_difficulty = (int)value;
                printf("Mining difficulty updated to %d.\n", mining_difficulty);
            }
        } else if (fields == 3 && strcmp(command, "borrow") == 0) {
            borrow_book(first, second);
        } else if (fields == 3 && strcmp(command, "return") == 0) {
            return_book(first, second, false);
        } else if (fields == 4 && strcmp(command, "return") == 0 && strcmp(third, "late") == 0) {
            return_book(first, second, true);
        } else if (fields == 1 && strcmp(command, "utxos") == 0) {
            print_utxo_set();
        } else if (fields == 2 && strcmp(command, "history") == 0) {
            print_member_history(first);
        } else if (fields == 6 && strcmp(command, "transfer") == 0) {
            char *end = NULL;
            long amount = strtol(third, &end, 10);
            long fee = strtol(fourth, &end, 10);
            unsigned long nonce = strtoul(fifth, &end, 10);
            if (amount <= 0 || fee < 0) {
                printf("ERROR: Invalid transfer values.\n");
            } else {
                submit_account_transfer(first, second, amount, fee, nonce);
            }
        } else {
            printf("ERROR: Invalid command. Type 'help' for available commands.\n");
        }
    }

    EVP_PKEY_free(signing_key);
    return EXIT_SUCCESS;
}
