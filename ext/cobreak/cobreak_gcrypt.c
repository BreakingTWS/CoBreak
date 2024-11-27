#include<cobreak_gcrypt.h>

VALUE mCoBreakGCrypt;
VALUE cCoBreakGCryptmd5;
VALUE cCoBreakGCrypttiger160;
VALUE cCoBreakGCryptdoublesha1;
VALUE cCoBreakGCryptblake2s_128;
VALUE cCoBreakGCryptblake2s_160;
VALUE cCoBreakGCryptblake2b_160;
VALUE cCoBreakGCryptblake2s_224;
VALUE cCoBreakGCryptblake2s_256;
VALUE cCoBreakGCryptblake2b_256;
VALUE cCoBreakGCryptblake2b_384;
VALUE cCoBreakGCryptblake2b_512;
VALUE cCoBreakGCrypthaval_160;
VALUE cCoBreakGCryptwhirlpool;
VALUE cCoBreakGCryptgost_streebog_256;
VALUE cCoBreakGCryptgost_streebog_512;
/*
VALUE md5_hexdigest(VALUE self, VALUE full) {
    char *str = RSTRING_PTR(full);
    int length = RSTRING_LEN(full); 
    gcry_md_hd_t handle;
    unsigned char digest[16]; 
    char out[41];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }

   
    gcry_md_open(&handle, GCRY_MD_MD5, 0);
    
    
    gcry_md_write(handle, str, length);
    
   
    memcpy(digest, gcry_md_read(handle, GCRY_MD_MD5), 16);
    gcry_md_close(handle);

    
    for (int n = 0; n < 16; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[41] = '\0'; 

    VALUE result = rb_str_new2(out); 
    return result;
}*/

VALUE tiger160_hexdigest(VALUE self, VALUE full) {
    char *str = RSTRING_PTR(full);
    int length = RSTRING_LEN(full); 
    gcry_md_hd_t handle;
    unsigned char digest[20]; 
    char out[41];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }

   
    gcry_md_open(&handle, GCRY_MD_TIGER, 0);
    
    
    gcry_md_write(handle, str, length);
    
   
    memcpy(digest, gcry_md_read(handle, GCRY_MD_TIGER), 20);
    gcry_md_close(handle);

    
    for (int n = 0; n < 20; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[40] = '\0'; 

    VALUE result = rb_str_new2(out); 
    return result;
}

VALUE double_sha1_hexdigest(VALUE self, VALUE full) {
    char *str = RSTRING_PTR(full);
    int length = RSTRING_LEN(full); 
    gcry_md_hd_t handle;
    unsigned char digest[20]; 
    unsigned char intermediate_digest[20]; 
    char out[41];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }


    gcry_md_open(&handle, GCRY_MD_SHA1, 0);

    
    gcry_md_write(handle, str, length);
    
   
    memcpy(intermediate_digest, gcry_md_read(handle, GCRY_MD_SHA1), 20);
    gcry_md_close(handle);


    gcry_md_open(&handle, GCRY_MD_SHA1, 0);
    

    gcry_md_write(handle, intermediate_digest, 20);
    

    memcpy(digest, gcry_md_read(handle, GCRY_MD_SHA1), 20);
    gcry_md_close(handle);

 
    for (int n = 0; n < 20; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[40] = '\0';

    VALUE result = rb_str_new2(out); // Crear una nueva cadena Ruby
    return result;
}

VALUE blake2s_128_hexdigest(VALUE self, VALUE input) {

    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input); 
    unsigned char digest[16];
    char out[33];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }


    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_BLAKE2S_128, 0);
    
   
    gcry_md_write(handle, str, length);
    

    memcpy(digest, gcry_md_read(handle, GCRY_MD_BLAKE2S_128), 16);
    gcry_md_close(handle);


    for (int n = 0; n < 16; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[32] = '\0';

    VALUE result = rb_str_new2(out);
    return result;
}

VALUE blake2s_160_hexdigest(VALUE self, VALUE input) {
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input);
    unsigned char digest[20];
    char out[41]; 

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }

    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_BLAKE2S_160, 0);
    
    gcry_md_write(handle, str, length);
    
    memcpy(digest, gcry_md_read(handle, GCRY_MD_BLAKE2S_160), 20);
    gcry_md_close(handle);

    for (int n = 0; n < 20; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[40] = '\0';

    VALUE result = rb_str_new2(out);
    return result;
}

VALUE blake2b_160_hexdigest(VALUE self, VALUE input) {
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input);
    unsigned char digest[20]; 
    char out[41]; 

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }


    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_BLAKE2B_160, 0);
    

    gcry_md_write(handle, str, length);
    

    memcpy(digest, gcry_md_read(handle, GCRY_MD_BLAKE2B_160), 20);
    gcry_md_close(handle);


    for (int n = 0; n < 20; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[40] = '\0';

    VALUE result = rb_str_new2(out); 
    return result;
}

VALUE blake2s_224_hexdigest(VALUE self, VALUE input) {
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input);
    unsigned char digest[28]; 
    char out[57];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }

    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_BLAKE2S_224, 0);
    
    gcry_md_write(handle, str, length);
    
    memcpy(digest, gcry_md_read(handle, GCRY_MD_BLAKE2S_224), 28);
    gcry_md_close(handle);

    for (int n = 0; n < 28; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[56] = '\0';

    VALUE result = rb_str_new2(out);
    return result;
}

VALUE blake2s_256_hexdigest(VALUE self, VALUE input) {
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input);
    unsigned char digest[32];
    char out[65];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }

    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_BLAKE2S_256, 0);

    gcry_md_write(handle, str, length);

    memcpy(digest, gcry_md_read(handle, GCRY_MD_BLAKE2S_256), 32);
    gcry_md_close(handle);

    for (int n = 0; n < 32; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[64] = '\0'; 

    VALUE result = rb_str_new2(out);
    return result;
}

VALUE blake2b_256_hexdigest(VALUE self, VALUE input) {
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input);
    unsigned char digest[32];
    char out[65];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }

    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_BLAKE2B_256, 0);

    gcry_md_write(handle, str, length);

    memcpy(digest, gcry_md_read(handle, GCRY_MD_BLAKE2B_256), 32);
    gcry_md_close(handle);

    for (int n = 0; n < 32; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[64] = '\0';

    VALUE result = rb_str_new2(out);
    return result;
}

VALUE blake2b_384_hexdigest(VALUE self, VALUE input) {
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input);
    unsigned char digest[48];
    char out[97];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }

    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_BLAKE2B_384, 0);
    
    gcry_md_write(handle, str, length);

    memcpy(digest, gcry_md_read(handle, GCRY_MD_BLAKE2B_384), 48);
    gcry_md_close(handle);

    for (int n = 0; n < 48; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[96] = '\0';

    VALUE result = rb_str_new2(out);
    return result;
}

VALUE blake2b_512_hexdigest(VALUE self, VALUE input) {
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input);
    unsigned char digest[64];
    char out[129];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "Versión de libgcrypt no compatible.");
    }

    gcry_md_hd_t handle;
    gcry_md_open(&handle, GCRY_MD_BLAKE2B_512, 0);

    gcry_md_write(handle, str, length);

    memcpy(digest, gcry_md_read(handle, GCRY_MD_BLAKE2B_512), 64);
    gcry_md_close(handle);

    for (int n = 0; n < 64; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[128] = '\0';

    VALUE result = rb_str_new2(out);
    return result;
}

VALUE whirlpool_hexdigest(VALUE self, VALUE input) {
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input);
    unsigned char digest[64];
    char out[129];

    if (!gcry_check_version(GCRYPT_VERSION)) {
        rb_raise(rb_eRuntimeError, "No se pudo inicializar la biblioteca Libgcrypt");
    }

    gcry_md_hd_t handle;
    if (gcry_md_open(&handle, GCRY_MD_WHIRLPOOL, 0) != 0) {
        rb_raise(rb_eRuntimeError, "No se pudo abrir el contexto de hashing");
    }

    gcry_md_write(handle, str, length);
    memcpy(digest, gcry_md_read(handle, 0), 64);

    gcry_md_close(handle);

    for (int n = 0; n < 64; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[128] = '\0';

    VALUE result = rb_str_new2(out);
    return result;
}

VALUE streebog_256_hexdigest(VALUE self, VALUE input) {
    gcry_check_version(GCRYPT_VERSION);
    const char* str_input = StringValueCStr(input);
    size_t input_len = strlen(str_input);
    gcry_md_hd_t handle;

    gcry_error_t err = gcry_md_open(&handle, GCRY_MD_STRIBOG256, GCRY_MD_FLAG_SECURE);
    if (err) {
        rb_raise(rb_eRuntimeError, "Error al abrir el contexto: %s", gcry_strerror(err));
    }

    gcry_md_write(handle, str_input, input_len);
    unsigned char* hash = gcry_md_read(handle, GCRY_MD_STRIBOG256);
    VALUE result = rb_str_new(NULL, gcry_md_get_algo_dlen(GCRY_MD_STRIBOG256) * 2);
    char *result_ptr = RSTRING_PTR(result);

    for (size_t i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_STRIBOG256); i++) {
        snprintf(result_ptr + i * 2, 3, "%02x", hash[i]);
    }
    gcry_md_close(handle);

    return result;
}

VALUE streebog_512_hexdigest(VALUE self, VALUE input) {

    gcry_check_version(GCRYPT_VERSION);
    const char* str_input = StringValueCStr(input);
    size_t input_len = strlen(str_input);
    gcry_md_hd_t handle;

    gcry_error_t err = gcry_md_open(&handle, GCRY_MD_STRIBOG512, GCRY_MD_FLAG_SECURE);
    if (err) {
        rb_raise(rb_eRuntimeError, "Error al abrir el contexto: %s", gcry_strerror(err));
    }

    gcry_md_write(handle, str_input, input_len);
    unsigned char* hash = gcry_md_read(handle, GCRY_MD_STRIBOG512);

    VALUE result = rb_str_new(NULL, gcry_md_get_algo_dlen(GCRY_MD_STRIBOG512) * 2);
    char *result_ptr = RSTRING_PTR(result);

    for (size_t i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_STRIBOG512); i++) {
        snprintf(result_ptr + i * 2, 3, "%02x", hash[i]);
    }

    gcry_md_close(handle);

    return result;
}

void init_cobreak_gcrypt(){
    //Define module GCrypt in mCoBreak
    mCoBreakGCrypt = rb_define_module_under(mCoBreak, "GCrypt");
    //Define Class MD5 encrypt mode
    //cCoBreakGCryptmd5 = rb_define_class_under(mCoBreakGCrypt, "MD5", rb_cObject);
    //rb_define_singleton_method(cCoBreakGCryptmd5, "hexdigest", md5_hexdigest, 1);
    //Define Class TIGER-160 encrypt mode
    cCoBreakGCrypttiger160 = rb_define_class_under(mCoBreakGCrypt, "TIGER_160", rb_cObject);
    rb_define_singleton_method(cCoBreakGCrypttiger160, "hexdigest", tiger160_hexdigest, 1);
    //Define Class DOUBLE SHA-1 encrypt mode
    cCoBreakGCryptdoublesha1 = rb_define_class_under(mCoBreakGCrypt, "DOUBLE_SHA1", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptdoublesha1, "hexdigest", double_sha1_hexdigest, 1);
    //Define Class BLAKE2S-128 encrypt mode
    cCoBreakGCryptblake2s_128 = rb_define_class_under(mCoBreakGCrypt, "BLAKE2S_128", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptblake2s_128, "hexdigest", blake2s_128_hexdigest, 1);
    //Define Class BLAKE2S-160 encrypt mode
    cCoBreakGCryptblake2s_160 = rb_define_class_under(mCoBreakGCrypt, "BLAKE2S_160", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptblake2s_160, "hexdigest", blake2s_160_hexdigest, 1);
    //Define Class BLAKE2B-160 encrypt mode
    cCoBreakGCryptblake2b_160 = rb_define_class_under(mCoBreakGCrypt, "BLAKE2B_160", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptblake2b_160, "hexdigest", blake2b_160_hexdigest, 1);
    //Define Class BLAKE2S-224 encrypt mode
    cCoBreakGCryptblake2s_224 = rb_define_class_under(mCoBreakGCrypt, "BLAKE2S_224", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptblake2s_224, "hexdigest", blake2s_224_hexdigest, 1);
    //Define Class BLAKE2S-256 encrypt mode
    cCoBreakGCryptblake2s_256 = rb_define_class_under(mCoBreakGCrypt, "BLAKE2S_256", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptblake2s_256, "hexdigest", blake2s_256_hexdigest, 1);
    //Define Class BLAKE2B-256 encrypt mode
    cCoBreakGCryptblake2b_256 = rb_define_class_under(mCoBreakGCrypt, "BLAKE2B_256", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptblake2b_256, "hexdigest", blake2b_256_hexdigest, 1);
    //Define Class BLAKE2B-384 encrypt mode
    cCoBreakGCryptblake2b_384 = rb_define_class_under(mCoBreakGCrypt, "BLAKE2B_384", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptblake2b_384, "hexdigest", blake2b_384_hexdigest, 1);
    //Define Class BLAKE2B-512 encrypt mode
    cCoBreakGCryptblake2b_512 = rb_define_class_under(mCoBreakGCrypt, "BLAKE2B_512", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptblake2b_512, "hexdigest", blake2b_512_hexdigest, 1);
    //Define Class WHIRLPOOL encrypt mode
    cCoBreakGCryptwhirlpool = rb_define_class_under(mCoBreakGCrypt, "WHIRLPOOL", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptwhirlpool, "hexdigest", whirlpool_hexdigest, 1);
    //Define Class GOST_STREEBOG_256 encrypt mode
    cCoBreakGCryptgost_streebog_256 = rb_define_class_under(mCoBreakGCrypt, "GOST_STREEBOG_256", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptgost_streebog_256, "hexdigest", streebog_256_hexdigest, 1);
    //Define Class GOST_STREEBOG_512 encrypt mode
    cCoBreakGCryptgost_streebog_512 = rb_define_class_under(mCoBreakGCrypt, "GOST_STREEBOG_512", rb_cObject);
    rb_define_singleton_method(cCoBreakGCryptgost_streebog_512, "hexdigest", streebog_512_hexdigest, 1);
}