#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_BOOKS 500
#define MAX_MEMBERS 500
#define MAX_BLOCKS 5000
#define HASH_HEX_LEN 65
#define SIGNATURE_MAX_LEN 72
#define BOOKS_FILE "books.txt"
#define MEMBERS_FILE "members.txt"
#define CHAIN_FILE "chain.dat"
#define KEY_FILE "library_private.pem"

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
    char action[10];
    char previous_hash[HASH_HEX_LEN];
    unsigned char signature[SIGNATURE_MAX_LEN];
    unsigned int signature_len;
    char hash[HASH_HEX_LEN];
} Block;

static Book books[MAX_BOOKS];
static Member members[MAX_MEMBERS];
static Block chain[MAX_BLOCKS];
static size_t book_count;
static size_t member_count;
static size_t chain_length;
static EVP_PKEY *signing_key;

static void trim(char *text) {
    char *start = text;
    size_t length;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') start++;
    if (start != text) memmove(text, start, strlen(start) + 1);
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
        if (line[0] == '\0') continue;
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
        if (line[0] == '\0') continue;
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
    for (size_t i = 0; i < book_count; i++) if (strcmp(books[i].book_id, id) == 0) return &books[i];
    return NULL;
}

static const Member *find_member(const char *id) {
    for (size_t i = 0; i < member_count; i++) if (strcmp(members[i].member_id, id) == 0) return &members[i];
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
    for (unsigned int i = 0; i < digest_length; i++) sprintf(output + (i * 2), "%02x", digest[i]);
    output[digest_length * 2] = '\0';
    EVP_MD_CTX_free(context);
}

static void block_payload(const Block *block, char *payload, size_t capacity) {
    snprintf(payload, capacity, "%d|%lld|%s|%s|%s|%s|%s|%s",
             block->index, (long long)block->timestamp, block->book_id, block->book_title,
             block->member_id, block->member_name, block->action, block->previous_hash);
}

static void calculate_hash(Block *block) {
    char payload[512];
    block_payload(block, payload, sizeof payload);
    sha256_hex(payload, strlen(payload), block->hash);
}

static int sign_block(Block *block) {
    char payload[512];
    size_t signature_length = sizeof block->signature;
    EVP_MD_CTX *context;
    block_payload(block, payload, sizeof payload);
    context = EVP_MD_CTX_new();
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
    EVP_MD_CTX *context;
    block_payload(block, payload, sizeof payload);
    context = EVP_MD_CTX_new();
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
        if (!signing_key) fprintf(stderr, "ERROR: Could not read %s.\n", KEY_FILE);
        return signing_key != NULL;
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
        if (file) fclose(file);
        return 0;
    }
    fclose(file);
    return 1;
}

static void make_genesis(void) {
    memset(&chain[0], 0, sizeof chain[0]);
    chain[0].index = 0;
    chain[0].timestamp = time(NULL);
    strcpy(chain[0].action, "GENESIS");
    memset(chain[0].previous_hash, '0', 64);
    chain[0].previous_hash[64] = '\0';
    strcpy(chain[0].member_name, "Blockchain genesis");
    calculate_hash(&chain[0]);
    chain_length = 1;
}

static int save_chain(void) {
    FILE *file = fopen(CHAIN_FILE, "wb");
    if (!file) {
        fprintf(stderr, "ERROR: Cannot save %s: %s\n", CHAIN_FILE, strerror(errno));
        return 0;
    }
    int result = fwrite(chain, sizeof(Block), chain_length, file) == chain_length;
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

static int book_is_on_loan(const char *book_id) {
    for (size_t i = chain_length; i > 1; i--) {
        Block *block = &chain[i - 1];
        if (strcmp(block->book_id, book_id) == 0) return strcmp(block->action, "BORROWED") == 0;
    }
    return 0;
}

static int append_transaction(const Book *book, const Member *member, const char *action) {
    Block *block;
    if (chain_length >= MAX_BLOCKS) {
        fprintf(stderr, "ERROR: Chain storage is full.\n");
        return 0;
    }
    block = &chain[chain_length];
    memset(block, 0, sizeof *block);
    block->index = (int)chain_length;
    block->timestamp = time(NULL);
    strcpy(block->book_id, book->book_id);
    strcpy(block->book_title, book->title);
    strcpy(block->member_id, member->member_id);
    strcpy(block->member_name, member->full_name);
    strcpy(block->action, action);
    strcpy(block->previous_hash, chain[chain_length - 1].hash);
    if (!sign_block(block)) {
        fprintf(stderr, "ERROR: Could not sign transaction.\n");
        return 0;
    }
    calculate_hash(block);
    chain_length++;
    if (!save_chain()) {
        chain_length--;
        return 0;
    }
    printf("Transaction recorded in block %d. Hash: %s\n", block->index, block->hash);
    return 1;
}

static void borrow_book(const char *book_id, const char *member_id) {
    const Book *book = find_book(book_id);
    const Member *member = find_member(member_id);
    if (!book || !member) {
        printf("ERROR: Book or Member not found.\n");
        return;
    }
    if (book_is_on_loan(book_id)) {
        printf("ERROR: Book is already on loan.\n");
        return;
    }
    append_transaction(book, member, "BORROWED");
}

static void return_book(const char *book_id, const char *member_id) {
    const Book *book = find_book(book_id);
    const Member *member = find_member(member_id);
    if (!book || !member) {
        printf("ERROR: Book or Member not found.\n");
        return;
    }
    if (!book_is_on_loan(book_id)) {
        printf("ERROR: Book has no active loan.\n");
        return;
    }
    append_transaction(book, member, "RETURNED");
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
    }
    if (valid) printf("VALID: Chain integrity and hash links verified (%zu blocks).\n", chain_length);
    return valid;
}

static void view_records(void) {
    for (size_t i = 1; i < chain_length; i++) {
        char time_text[32];
        struct tm *time_info = localtime(&chain[i].timestamp);
        strftime(time_text, sizeof time_text, "%Y-%m-%d %H:%M:%S", time_info);
        printf("\nBlock %d | %s\nBook: %s (%s)\nMember: %s (%s)\nAction: %s\nSignature: %s\n",
               chain[i].index, time_text, chain[i].book_title, chain[i].book_id,
               chain[i].member_name, chain[i].member_id, chain[i].action,
               verify_signature(&chain[i]) ? "VALID" : "INVALID");
    }
    if (chain_length == 1) printf("No lending records yet.\n");
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

static void print_help(void) {
    printf("\nCommands:\n  borrow BOOK_ID MEMBER_ID\n  return BOOK_ID MEMBER_ID\n  view\n  validate\n  tamper\n  help\n  exit\n");
}

int main(void) {
    char line[160];
    char command[20];
    char first[40];
    char second[40];
    OpenSSL_add_all_algorithms();
    if (!load_books() || !load_members() || !load_or_create_key() || !load_chain()) return EXIT_FAILURE;
    printf("Library Lending Blockchain\nLoaded %zu books and %zu members.\n", book_count, member_count);
    print_help();
    while (printf("\n> ") && fgets(line, sizeof line, stdin)) {
        int fields = sscanf(line, "%19s %39s %39s", command, first, second);
        if (fields == 1 && strcmp(command, "view") == 0) view_records();
        else if (fields == 1 && strcmp(command, "validate") == 0) validate_chain();
        else if (fields == 1 && strcmp(command, "tamper") == 0) demonstrate_tamper();
        else if (fields == 1 && strcmp(command, "help") == 0) print_help();
        else if (fields == 1 && strcmp(command, "exit") == 0) break;
        else if (fields == 3 && strcmp(command, "borrow") == 0) borrow_book(first, second);
        else if (fields == 3 && strcmp(command, "return") == 0) return_book(first, second);
        else printf("ERROR: Invalid command. Type 'help' for available commands.\n");
    }
    EVP_PKEY_free(signing_key);
    return EXIT_SUCCESS;
}
