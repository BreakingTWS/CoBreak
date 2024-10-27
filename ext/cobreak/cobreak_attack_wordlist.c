#include<cobreak_attack_wordlist.h>

VALUE mCoBreakAttackWordlist;
VALUE cCoBreakAttackWordlistMD5;

#define BLOCK_SIZE 1024

void calcular_hash_md5(const char *cadena, unsigned char *hash) {
    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_MD5, 0);
    gcry_md_write(handle, cadena, strlen(cadena));
    gcry_md_final(handle);
    memcpy(hash, gcry_md_read(handle, GCRY_MD_MD5), 16);
    gcry_md_close(handle);
}

int comparar_hashes(const unsigned char *hash1, const unsigned char *hash2) {
    return memcmp(hash1, hash2, 16) == 0;
}

void hex_a_hash(const char *hex, unsigned char *hash) {
    for (size_t i = 0; i < 16; i++) {
        sscanf(hex + 2 * i, "%2hhx", &hash[i]);
    }
}

VALUE attackwordlist_md5(VALUE self, VALUE hash, VALUE dictionary) {
    FILE *archivo = fopen(StringValueCStr(dictionary), "r");
    if (archivo == NULL) {
        rb_raise(rb_eIOError, "Error al abrir el archivo de texto");
    }

    unsigned char hash_objetivo[16];
    hex_a_hash(StringValueCStr(hash), hash_objetivo);
    
    VALUE found_password = Qnil;
    unsigned char hash_actual[16];
    
    char *lineas[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        lineas[i] = malloc(256 * sizeof(char));
        if (lineas[i] == NULL) {
            fclose(archivo);
            rb_raise(rb_eRuntimeError, "Error de asignación de memoria");
        }
    }

    while (1) {
        size_t count = 0;

        for (size_t i = 0; i < BLOCK_SIZE && fgets(lineas[count], 256, archivo); i++) {
            lineas[count][strcspn(lineas[count], "\r\n")] = 0; 
            count++;
        }

        if (count == 0) {
            break;
        }

        for (size_t i = 0; i < count; i++) {
            calcular_hash_md5(lineas[i], hash_actual);

            if (comparar_hashes(hash_actual, hash_objetivo)) {
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
    VALUE mCoBreakAttackWordlist = rb_define_module("AttackWordlist");
    
    //Define class MD5 for AttackWordlist
    cCoBreakAttackWordlistMD5 = rb_define_class_under(mCoBreakAttackWordlist, "MD5", rb_cObject);
    rb_define_singleton_method(cCoBreakAttackWordlistMD5, "crack", attackwordlist_md5, 2);
}