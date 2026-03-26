#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>

#define KEY_LEN 16
#define IV_LEN 16
#define MAX_WORD_LEN 256

/* convert one hex character to its integer value. */
int hex_char_to_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

/* convert a hex string into raw bytes. */
int hex_to_bytes(const char *hex_string, unsigned char *output_bytes, int max_output_len)
{
    int hex_length = (int)strlen(hex_string);

    /* the hex string must have an even number of characters. */
    if (hex_length % 2 != 0)
    {
        return -1;
    }

    int output_length = hex_length / 2;

    if (output_length > max_output_len)
    {
        return -1;
    }

    for (int i = 0; i < output_length; i++)
    {
        int high_nibble = hex_char_to_value(hex_string[i * 2]);
        int low_nibble  = hex_char_to_value(hex_string[i * 2 + 1]);

        if (high_nibble < 0 || low_nibble < 0)
        {
            return -1;
        }

        output_bytes[i] = (unsigned char)((high_nibble << 4) | low_nibble);
    }

    return output_length;
}

/* remove trailing newline and carriage return characters from a line. */
void strip_newline(char *line)
{
    size_t length = strlen(line);

    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
    {
        line[length - 1] = '\0';
        length--;
    }
}

/* encrypt plaintext using aes-128-cbc with openssl evp. */
int aes_128_cbc_encrypt(
    const unsigned char *plaintext,
    int plaintext_len,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *ciphertext
)
{
    EVP_CIPHER_CTX *context = NULL;
    int output_len_part_1 = 0;
    int output_len_part_2 = 0;
    int total_ciphertext_len = 0;

    context = EVP_CIPHER_CTX_new();
    if (context == NULL)
    {
        return -1;
    }

    if (EVP_EncryptInit_ex(context, EVP_aes_128_cbc(), NULL, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(context);
        return -1;
    }

    if (EVP_EncryptUpdate(context, ciphertext, &output_len_part_1, plaintext, plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(context);
        return -1;
    }

    if (EVP_EncryptFinal_ex(context, ciphertext + output_len_part_1, &output_len_part_2) != 1)
    {
        EVP_CIPHER_CTX_free(context);
        return -1;
    }

    total_ciphertext_len = output_len_part_1 + output_len_part_2;

    EVP_CIPHER_CTX_free(context);
    return total_ciphertext_len;
}

int main(int argc, char *argv[])
{
    /* expected usage:
       ./task7_bruteforce wordlist.txt
    */

    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <wordlist_file>\n", argv[0]);
        return 1;
    }

    const unsigned char plaintext[] = "This is a top secret.";
    const int plaintext_len = 21;

    const char *target_ciphertext_hex =
        "764aa26b55a4da654df6b19e4bce00f4"
        "ed05e09346fb0e762583cb7da2ac93a2";

    const char *iv_hex = "aabbccddeeff00998877665544332211";

    unsigned char target_ciphertext[128];
    unsigned char iv[IV_LEN];
    int target_ciphertext_len = 0;
    int iv_len = 0;

    target_ciphertext_len = hex_to_bytes(target_ciphertext_hex, target_ciphertext, sizeof(target_ciphertext));
    iv_len = hex_to_bytes(iv_hex, iv, sizeof(iv));

    if (target_ciphertext_len < 0 || iv_len != IV_LEN)
    {
        fprintf(stderr, "failed to parse target ciphertext or iv.\n");
        return 1;
    }

    FILE *word_file = fopen(argv[1], "r");
    if (word_file == NULL)
    {
        perror("failed to open word list");
        return 1;
    }

    char word_buffer[MAX_WORD_LEN];

    while (fgets(word_buffer, sizeof(word_buffer), word_file) != NULL)
    {
        strip_newline(word_buffer);

        /* skip empty lines. */
        if (word_buffer[0] == '\0')
        {
            continue;
        }

        int word_len = (int)strlen(word_buffer);

        /* the word must be shorter than 16 characters per lab instructions. */
        if (word_len >= KEY_LEN)
        {
            continue;
        }

        unsigned char candidate_key[KEY_LEN];
        unsigned char produced_ciphertext[128];

        /* fill the entire key with '#'. */
        memset(candidate_key, '#', KEY_LEN);

        /* copy the word into the front of the key. */
        memcpy(candidate_key, word_buffer, word_len);

        int produced_ciphertext_len = aes_128_cbc_encrypt(
            plaintext,
            plaintext_len,
            candidate_key,
            iv,
            produced_ciphertext
        );

        if (produced_ciphertext_len < 0)
        {
            fprintf(stderr, "encryption failed for candidate word: %s\n", word_buffer);
            fclose(word_file);
            return 1;
        }

        if (produced_ciphertext_len == target_ciphertext_len &&
            memcmp(produced_ciphertext, target_ciphertext, target_ciphertext_len) == 0)
        {
            printf("match found.\n");
            printf("dictionary word: %s\n", word_buffer);
            printf("full 16-byte key: ");

            for (int i = 0; i < KEY_LEN; i++)
            {
                printf("%c", candidate_key[i]);
            }
            printf("\n");

            fclose(word_file);
            return 0;
        }
    }

    fclose(word_file);

    printf("no matching word found in the provided word list.\n");
    return 0;
}