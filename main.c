#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/evp.h>

#define DATABASE_NAME "database.db"
#define KEY "EncryptionKey"

sqlite3* db;

void initializeDatabase() {
    int rc = sqlite3_open(DATABASE_NAME, &db);

    if (rc) {
        fprintf(stderr, "Cannot open the database: %s\n", sqlite3_errmsg(db));
        exit(1);
    } else {
        fprintf(stdout, "The database has been successfully opened\n");
    }

    // Create a table if it does not exist
    char* createTableSQL = "CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, data TEXT);";
    rc = sqlite3_exec(db, createTableSQL, 0, 0, 0);

    if (rc) {
        fprintf(stderr, "Error when creating a table: %s\n", sqlite3_errmsg(db));
        exit(1);
    }
}

void encryptAndInsertData() {
    char data[256];
    printf("Enter the data to be encrypted and inserted into the database: ");

    fgets(data, sizeof(data), stdin);

    // Delete the newline character, if any
    size_t len = strlen(data);
    if (len > 0 && data[len - 1] == '\n') {
        data[len - 1] = '\0';
        len--; // Decrease the length by 1 because the newline character has been deleted
    }

    // OpenSSL initialization
    OpenSSL_add_all_algorithms();

    // Key initialization and IV
    unsigned char key[32];
    unsigned char iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, (unsigned char*)KEY, strlen(KEY), 1, key, iv);

    // Creating and configuring the encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int out_len; // Variable for storing the length of encrypted data
    unsigned char ciphertext[256];

    // Data encryption
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, (unsigned char*)data, len);
    int ciphertext_len = out_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len);
    ciphertext_len += out_len;

    // Inserting encrypted data into the database
    char insertSQL[512];
    snprintf(insertSQL, sizeof(insertSQL), "INSERT INTO data (data) VALUES (?);");
    sqlite3_stmt* stmt;

    int rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error in preparing a request: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    sqlite3_bind_blob(stmt, 1, ciphertext, ciphertext_len, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error when inserting data: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    sqlite3_finalize(stmt);
    EVP_CIPHER_CTX_free(ctx);

    printf("The data has been successfully encrypted and inserted into the database\n");
}

void decryptAndPrintData(const unsigned char* ciphertext, int ciphertext_len) {
    // OpenSSL initialization
    OpenSSL_add_all_algorithms();

    // Key initialization and IV
    unsigned char key[32];
    unsigned char iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, (unsigned char*)KEY, strlen(KEY), 1, key, iv);

    // Creating and customizing the transcript context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char plaintext[256];

    // Data decoding
    int out_len;
    EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len);
    int plaintext_len = out_len;

    EVP_DecryptFinal_ex(ctx, plaintext + out_len, &out_len);
    plaintext_len += out_len;

    EVP_CIPHER_CTX_free(ctx);

    // Print only the actual data, not the entire buffer
    printf("Decrypted data: %.*s\n", plaintext_len, plaintext);
}

void printDataFromDatabase() {
    char* selectSQL = "SELECT id, data FROM data;";
    sqlite3_stmt* stmt;

    int rc = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, 0);

    if (rc) {
        fprintf(stderr, "Error during query execution: %s\n", sqlite3_errmsg(db));
    } else {
        printf("Data in the database:\n");

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            const unsigned char* data = sqlite3_column_blob(stmt, 1);
            int data_len = sqlite3_column_bytes(stmt, 1);

            printf("ID: %d\n", id);
            printf("Encrypted data: "); // Changing the output for encrypted data
            for (int i = 0; i < data_len; i++) {
                printf("%02x", data[i]);
            }
            printf("\n");
            decryptAndPrintData(data, data_len);
        }

        sqlite3_finalize(stmt);
    }
}

int main() {
    initializeDatabase();

    int choice;

    do {
        printf("\nMenu:\n");
        printf("1. Encrypt and insert data into the database\n");
        printf("2. Output data from the database\n");
        printf("3. Exit\n");
        printf("Select an action: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                getchar(); // Added getchar() call to remove newline character from buffer
                encryptAndInsertData();
                break;
            case 2:
                printDataFromDatabase();
                break;
            case 3:
                printf("Exiting the program.\n");
                break;
            default:
                printf("This is an unacceptable choice. Please repeat.\n");
                break;
        }
    } while (choice != 3);

    sqlite3_close(db);
    return 0;
}
