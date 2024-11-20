#include<cobreak_attack_wordlist.h>

VALUE mCoBreakAttackWordlist;
VALUE cCoBreakAttackWordlistMD4;
VALUE cCoBreakAttackWordlistMD5;
VALUE cCoBreakAttackWordlistHALF_MD5;
VALUE cCoBreakAttackWordlistSHA1;
VALUE cCoBreakAttackWordlistDouble_SHA1;
VALUE cCoBreakAttackWordlistSHA2_224;

#define BLOCK_SIZE 1024
#define MAX_HASH_LENGTH_MD 16
#define MAX_LINE_LENGTH 256

//Define MD5 Crack
void calcular_hash_md4(const char *cadena, unsigned char *hash) {
    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_MD4, 0);
    gcry_md_write(handle, cadena, strlen(cadena));
    gcry_md_final(handle);
    memcpy(hash, gcry_md_read(handle, GCRY_MD_MD4), MAX_HASH_LENGTH_MD);
    gcry_md_close(handle);
}

int comparar_hashes_md4(const unsigned char *hash1, const unsigned char *hash2) {
    return memcmp(hash1, hash2, MAX_HASH_LENGTH_MD) == 0;
}

void hex_a_hash_md4(const char *hex, unsigned char *hash) {
    for (size_t i = 0; i < MAX_HASH_LENGTH_MD; i++) {
        sscanf(hex + 2 * i, "%2hhx", &hash[i]);
    }
}

VALUE attackwordlist_md4(VALUE self, VALUE hash, VALUE dictionary) {
    FILE *archivo = fopen(StringValueCStr(dictionary), "r");
    if (archivo == NULL) {
        rb_raise(rb_eIOError, "Error al abrir el archivo de texto");
    }

    unsigned char hash_objetivo[MAX_HASH_LENGTH_MD];
    hex_a_hash_md4(StringValueCStr(hash), hash_objetivo);
    
    VALUE found_password = Qnil;
    unsigned char hash_actual[MAX_HASH_LENGTH_MD];
    
    char *lineas[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        lineas[i] = malloc(MAX_LINE_LENGTH * sizeof(char));
        if (lineas[i] == NULL) {
            fclose(archivo);
            rb_raise(rb_eRuntimeError, "Error de asignación de memoria");
        }
    }

    while (1) {
        size_t count = 0;

        for (size_t i = 0; i < BLOCK_SIZE && fgets(lineas[count], MAX_LINE_LENGTH, archivo); i++) {
            lineas[count][strcspn(lineas[count], "\r\n")] = 0;
            count++;
        }

        if (count == 0) {
            break;
        }

        for (size_t i = 0; i < count; i++) {
            calcular_hash_md4(lineas[i], hash_actual);

            if (comparar_hashes_md4(hash_actual, hash_objetivo)) {
                if (found_password == Qnil) {
                    found_password = rb_str_new_cstr(lineas[i]);
                }
            }
        }
    }

    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        free(lineas[i]);
    }
    fclose(archivo);
    
    return found_password;
}

//Define MD5 Crack
void calcular_hash_md5(const char *cadena, unsigned char *hash) {
    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_MD5, 0);
    gcry_md_write(handle, cadena, strlen(cadena));
    gcry_md_final(handle);
    memcpy(hash, gcry_md_read(handle, GCRY_MD_MD5), MAX_HASH_LENGTH_MD);
    gcry_md_close(handle);
}

int comparar_hashes_md5(const unsigned char *hash1, const unsigned char *hash2) {
    return memcmp(hash1, hash2, MAX_HASH_LENGTH_MD) == 0;
}

void hex_a_hash_md5(const char *hex, unsigned char *hash) {
    for (size_t i = 0; i < MAX_HASH_LENGTH_MD; i++) {
        sscanf(hex + 2 * i, "%2hhx", &hash[i]);
    }
}

VALUE attackwordlist_md5(VALUE self, VALUE hash, VALUE dictionary) {
    
    FILE *archivo = fopen(StringValueCStr(dictionary), "r");
    if (archivo == NULL) {
        rb_raise(rb_eIOError, "Error al abrir el archivo de texto");
    }
    
    unsigned char hash_objetivo[MAX_HASH_LENGTH_MD];
    hex_a_hash_md5(StringValueCStr(hash), hash_objetivo);
    
    VALUE found_password = Qnil;
    unsigned char hash_actual[MAX_HASH_LENGTH_MD];
    
    char *lineas[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        lineas[i] = malloc(MAX_LINE_LENGTH * sizeof(char));
        if (lineas[i] == NULL) {
            fclose(archivo);
            rb_raise(rb_eRuntimeError, "Error de asignación de memoria");
        }
    }

    while (1) {
        size_t count = 0;

        for (size_t i = 0; i < BLOCK_SIZE && fgets(lineas[count], MAX_LINE_LENGTH, archivo); i++) {
            lineas[count][strcspn(lineas[count], "\r\n")] = 0; 
            count++;
        }

        if (count == 0) {
            break;
        }

        for (size_t i = 0; i < count; i++) {
            calcular_hash_md5(lineas[i], hash_actual);

            if (comparar_hashes_md5(hash_actual, hash_objetivo)) {
                if (found_password == Qnil) {
                    found_password = rb_str_new_cstr(lineas[i]);
                }
            }
        }
    }

    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        free(lineas[i]);
    }
    fclose(archivo);
    
    return found_password;
}

//Define Half MD5 Crack
int comparar_hashes_half_md5(const unsigned char *hash1, const unsigned char *hash2) {
    return memcmp(hash1, hash2, 8) == 0;
}

void hex_a_hash_half_md5(const char *hex, unsigned char *hash) {
    for (size_t i = 0; i < 8; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &hash[i]) != 1) {
            rb_raise(rb_eArgError, "Error al convertir el hash hexadecimal");
        }
    }
}

VALUE attackwordlist_half_md5(VALUE self, VALUE hash, VALUE dictionary) {
    FILE *archivo = fopen(StringValueCStr(dictionary), "r");
    if (archivo == NULL) {
        rb_raise(rb_eIOError, "Error al abrir el archivo de texto");
    }

    unsigned char hash_objetivo[8];
    hex_a_hash_half_md5(StringValueCStr(hash), hash_objetivo);
    
    VALUE found_password = Qnil;
    unsigned char hash_actual[MAX_HASH_LENGTH_MD];
    
    char *lineas[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        lineas[i] = malloc(MAX_LINE_LENGTH * sizeof(char));
        if (lineas[i] == NULL) {
            fclose(archivo);
            rb_raise(rb_eRuntimeError, "Error de asignación de memoria");
        }
    }

    while (1) {
        size_t count = 0;

        for (size_t i = 0; i < BLOCK_SIZE && fgets(lineas[count], MAX_LINE_LENGTH, archivo); i++) {
            lineas[count][strcspn(lineas[count], "\r\n")] = 0;
            count++;
        }

        if (count == 0) {
            break;
        }

        for (size_t i = 0; i < count; i++) {
            calcular_hash_md5(lineas[i], hash_actual);

            unsigned char half_hash_actual[8];
            memcpy(half_hash_actual, hash_actual, 8);

            if (comparar_hashes_half_md5(half_hash_actual, hash_objetivo)) {
                if (found_password == Qnil) {
                    found_password = rb_str_new_cstr(lineas[i]);
                }
            }
        }
    }

    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        free(lineas[i]);
    }
    fclose(archivo);
    
    return found_password;
}

//Define SHA-1 Crack
void calcular_hash_sha1(const char *cadena, unsigned char *hash) {
    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_SHA1, 0);
    gcry_md_write(handle, cadena, strlen(cadena));
    gcry_md_final(handle);
    memcpy(hash, gcry_md_read(handle, GCRY_MD_SHA1), 20);
    gcry_md_close(handle);
}

int comparar_hashes_sha1(const unsigned char *hash1, const unsigned char *hash2) {
    return memcmp(hash1, hash2, 20) == 0;
}

void hex_a_hash_sha1(const char *hex, unsigned char *hash) {
    for (size_t i = 0; i < 20; i++) {
        sscanf(hex + 2 * i, "%2hhx", &hash[i]);
    }
}

VALUE attackwordlist_sha1(VALUE self, VALUE hash, VALUE dictionary) {
    FILE *archivo = fopen(StringValueCStr(dictionary), "r");
    if (archivo == NULL) {
        rb_raise(rb_eIOError, "Error al abrir el archivo de texto");
    }

    unsigned char hash_objetivo[20];
    hex_a_hash_sha1(StringValueCStr(hash), hash_objetivo);
    
    VALUE found_password = Qnil;
    unsigned char hash_actual[20];
    
    char *lineas[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        lineas[i] = malloc(MAX_LINE_LENGTH * sizeof(char));
        if (lineas[i] == NULL) {
            fclose(archivo);
            rb_raise(rb_eRuntimeError, "Error de asignación de memoria");
        }
    }

    while (1) {
        size_t count = 0;

        for (size_t i = 0; i < BLOCK_SIZE && fgets(lineas[count], MAX_LINE_LENGTH, archivo); i++) {
            lineas[count][strcspn(lineas[count], "\r\n")] = 0; // Eliminar nueva línea
            count++;
        }

        if (count == 0) {
            break;
        }

        for (size_t i = 0; i < count; i++) {
            calcular_hash_sha1(lineas[i], hash_actual);
 
            if (comparar_hashes_sha1(hash_actual, hash_objetivo)) {
                if (found_password == Qnil) {
                    found_password = rb_str_new_cstr(lineas[i]);
                }
            }
        }
    }

    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        free(lineas[i]);
    }
    fclose(archivo);
    
    return found_password;
}

//Define Double SHA-1 Crack
void calcular_hash_double_sha1(const char *cadena, unsigned char *hash) {
    gcry_md_hd_t handle;
    unsigned char hash_intermedio[20];

    // Primer hash SHA-1
    gcry_md_open(&handle, GCRY_MD_SHA1, 0);
    gcry_md_write(handle, cadena, strlen(cadena));
    gcry_md_final(handle);
    memcpy(hash_intermedio, gcry_md_read(handle, GCRY_MD_SHA1), 20);
    gcry_md_close(handle);

    // Segundo hash SHA-1
    gcry_md_open(&handle, GCRY_MD_SHA1, 0);
    gcry_md_write(handle, hash_intermedio, 20);
    gcry_md_final(handle);
    memcpy(hash, gcry_md_read(handle, GCRY_MD_SHA1), 20);
    gcry_md_close(handle);
}

VALUE attackwordlist_double_sha1(VALUE self, VALUE hash, VALUE dictionary) {
    FILE *archivo = fopen(StringValueCStr(dictionary), "r");
    if (archivo == NULL) {
        rb_raise(rb_eIOError, "Error al abrir el archivo de texto");
    }

    unsigned char hash_objetivo[20];
    hex_a_hash_sha1(StringValueCStr(hash), hash_objetivo);
    
    VALUE found_password = Qnil;
    unsigned char hash_actual[20];
    
    char *lineas[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        lineas[i] = malloc(MAX_LINE_LENGTH * sizeof(char));
        if (lineas[i] == NULL) {
            fclose(archivo);
            rb_raise(rb_eRuntimeError, "Error de asignación de memoria");
        }
    }

    while (1) {
        size_t count = 0;

        for (size_t i = 0; i < BLOCK_SIZE && fgets(lineas[count], MAX_LINE_LENGTH, archivo); i++) {
            lineas[count][strcspn(lineas[count], "\r\n")] = 0; // Eliminar nueva línea
            count++;
        }

        if (count == 0) {
            break;
        }

        for (size_t i = 0; i < count; i++) {
            calcular_hash_double_sha1(lineas[i], hash_actual);
 
            if (comparar_hashes_sha1(hash_actual, hash_objetivo)) {
                if (found_password == Qnil) {
                    found_password = rb_str_new_cstr(lineas[i]);
                }
            }
        }
    }

    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        free(lineas[i]);
    }
    fclose(archivo);
    
    return found_password;
}

//Define SHA2-224 Crack
void calcular_sha2_224(const char *cadena, unsigned char *hash) {
    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_SHA224, 0);
    gcry_md_write(handle, cadena, strlen(cadena));
    gcry_md_final(handle);
    memcpy(hash, gcry_md_read(handle, GCRY_MD_SHA224), 28);
    gcry_md_close(handle);
}

int comparar_hashes_sha2_224(const unsigned char *hash1, const unsigned char *hash2) {
    return memcmp(hash1, hash2, 28) == 0;
}

void hex_a_hash_sha2_224(const char *hex, unsigned char *hash) {
    for (size_t i = 0; i < 28; i++) {
        sscanf(hex + 2 * i, "%2hhx", &hash[i]);
    }
}

VALUE attackwordlist_sha2_224(VALUE self, VALUE hash, VALUE dictionary) {
    FILE *archivo = fopen(StringValueCStr(dictionary), "r");
    if (archivo == NULL) {
        rb_raise(rb_eIOError, "Error al abrir el archivo de texto");
    }

    unsigned char hash_objetivo[28];
    hex_a_hash_sha2_224(StringValueCStr(hash), hash_objetivo);
    
    VALUE found_password = Qnil;
    unsigned char hash_actual[28];
    
    char *lineas[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        lineas[i] = malloc(MAX_LINE_LENGTH * sizeof(char));
        if (lineas[i] == NULL) {
            fclose(archivo);
            rb_raise(rb_eRuntimeError, "Error de asignación de memoria");
        }
    }

    while (1) {
        size_t count = 0;

        for (size_t i = 0; i < BLOCK_SIZE && fgets(lineas[count], MAX_LINE_LENGTH, archivo); i++) {
            lineas[count][strcspn(lineas[count], "\r\n")] = 0; // Eliminar nueva línea
            count++;
        }

        if (count == 0) {
            break;
        }

        for (size_t i = 0; i < count; i++) {
            calcular_sha2_224(lineas[i], hash_actual);
 
            if (comparar_hashes_sha2_224(hash_actual, hash_objetivo)) {
                if (found_password == Qnil) {
                    found_password = rb_str_new_cstr(lineas[i]);
                }
            }
        }
    }

    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        free(lineas[i]);
    }
    fclose(archivo);
    
    return found_password;
}

void init_cobreak_attack_wordlist() {
    //Define module AttackWordlist in mCoBreak
    VALUE mCoBreakAttackWordlist = rb_define_module_under(mCoBreak, "AttackWordlist");
    
    //Define class MD4 for AttackWordlist
    cCoBreakAttackWordlistMD4 = rb_define_class_under(mCoBreakAttackWordlist, "MD4", rb_cObject);
    rb_define_singleton_method(cCoBreakAttackWordlistMD4, "crack", attackwordlist_md4, 2);

    //Define class MD5 for AttackWordlist
    cCoBreakAttackWordlistMD5 = rb_define_class_under(mCoBreakAttackWordlist, "MD5", rb_cObject);
    rb_define_singleton_method(cCoBreakAttackWordlistMD5, "crack", attackwordlist_md5, 2);

    //Define class Half MD5 for AttackWordlist
    cCoBreakAttackWordlistHALF_MD5 = rb_define_class_under(mCoBreakAttackWordlist, "HALF_MD5", rb_cObject);
    rb_define_singleton_method(cCoBreakAttackWordlistHALF_MD5, "crack", attackwordlist_half_md5, 2);

    //Define class SHA1 for AttackWordlist
    cCoBreakAttackWordlistSHA1 = rb_define_class_under(mCoBreakAttackWordlist, "SHA1", rb_cObject);
    rb_define_singleton_method(cCoBreakAttackWordlistSHA1, "crack", attackwordlist_sha1, 2);

    //Define class Double SHA1 for AttackWordlist
    cCoBreakAttackWordlistDouble_SHA1 = rb_define_class_under(mCoBreakAttackWordlist, "DOUBLE_SHA1", rb_cObject);
    rb_define_singleton_method(cCoBreakAttackWordlistDouble_SHA1, "crack", attackwordlist_double_sha1, 2);

    //Define class SHA2-224 for AttackWordlist
    cCoBreakAttackWordlistSHA2_224 = rb_define_class_under(mCoBreakAttackWordlist, "SHA2_224", rb_cObject);
    rb_define_singleton_method(cCoBreakAttackWordlistSHA2_224, "crack", attackwordlist_sha2_224, 2);
}