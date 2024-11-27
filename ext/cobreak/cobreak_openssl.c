#include<cobreak_openssl.h>
#define BLOCK_SIZE 64
#define HASH_SIZE_512 64
#define HASH_SIZE 32
#define NUM_ROUNDS 12

VALUE mCoBreakOpenSSL;
VALUE cCoBreakOpenSSLhalf_md5;
VALUE cCoBreakOpenSSLsha1;
VALUE cCoBreakOpenSSLsha2_224;
VALUE cCoBreakOpenSSLsha2_256;
VALUE cCoBreakOpenSSLsha2_384;
VALUE cCoBreakOpenSSLsha2_512;
VALUE cCoBreakOpenSSLsha3_224;
VALUE cCoBreakOpenSSLsha3_256;
VALUE cCoBreakOpenSSLsha3_384;
VALUE cCoBreakOpenSSLsha3_512;
VALUE cCoBreakOpenSSLripemd160;


VALUE ripemd160_hexdigest(VALUE self, VALUE full){
	char *str = RSTRING_PTR(full);
	int n;
	RIPEMD160_CTX c;
	unsigned char digest[65];
	char *out = (char*)malloc(33);
	int length = strlen(str);

    RIPEMD160_Init(&c);

    while (length > 0) {
        if (length > 512) {
            RIPEMD160_Update(&c, str, 512);
        } else {
            RIPEMD160_Update(&c, str, length);
        }
        length -= 512;
	str += 512;
    }

    RIPEMD160_Final(digest, &c);

    for (n = 0; n < RIPEMD160_DIGEST_LENGTH; ++n) {
        snprintf(&(out[n*2]), RIPEMD160_DIGEST_LENGTH*2, "%02x", (unsigned int)digest[n]);
    }

    return rb_str_new2(out);
    free(out);
}

VALUE md4_hexdigest(VALUE self, VALUE input) {
    // Convertir el valor Ruby a una cadena C
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input); // Obtener la longitud de la cadena
    unsigned char digest[MD4_DIGEST_LENGTH]; // MD4 produce un hash de 16 bytes
    char out[33]; // 16 bytes * 2 para hexadecimal + 1 para el terminador

    // Calcular el hash MD4
    MD4((unsigned char*)str, length, digest);

    // Convertir el hash a una cadena hexadecimal
    for (int n = 0; n < MD4_DIGEST_LENGTH; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[32] = '\0'; // Terminar la cadena

    VALUE result = rb_str_new2(out); // Crear una nueva cadena Ruby
    return result;
}

VALUE half_md5_hexdigest(VALUE self, VALUE input) {
    // Convertir el valor Ruby a una cadena C
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input); // Obtener la longitud de la cadena
    unsigned char digest[MD5_DIGEST_LENGTH]; // MD5 produce un hash de 16 bytes
    char out[17]; // 8 bytes * 2 para hexadecimal + 1 para el terminador

    // Calcular el hash MD5
    MD5((unsigned char*)str, length, digest);

    // Convertir solo los primeros 8 bytes del hash a una cadena hexadecimal
    for (int n = 0; n < 8; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[16] = '\0'; // Terminar la cadena

    VALUE result = rb_str_new2(out); // Crear una nueva cadena Ruby
    return result;
}

VALUE sha1_hexdigest(VALUE self, VALUE input) {
    // Convertir el valor Ruby a una cadena C
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input); // Obtener la longitud de la cadena
    unsigned char digest[SHA_DIGEST_LENGTH]; // SHA-1 produce un hash de 20 bytes
    char out[41]; // 20 bytes * 2 para hexadecimal + 1 para el terminador

    // Calcular el hash SHA-1
    SHA1((unsigned char*)str, length, digest);

    // Convertir el hash a una cadena hexadecimal
    for (int n = 0; n < SHA_DIGEST_LENGTH; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[40] = '\0'; // Terminar la cadena

    VALUE result = rb_str_new2(out); // Crear una nueva cadena Ruby
    return result;
}

VALUE sha2_224_hexdigest(VALUE self, VALUE input) {
    // Convertir el valor Ruby a una cadena C
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input); // Obtener la longitud de la cadena
    unsigned char digest[SHA224_DIGEST_LENGTH]; // SHA-224 produce un hash de 28 bytes
    char out[57]; // 28 bytes * 2 para hexadecimal + 1 para el terminador

    // Calcular el hash SHA-224
    SHA224((unsigned char*)str, length, digest);

    // Convertir el hash a una cadena hexadecimal
    for (int n = 0; n < SHA224_DIGEST_LENGTH; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[56] = '\0'; // Terminar la cadena

    VALUE result = rb_str_new2(out); // Crear una nueva cadena Ruby
    return result;
}

VALUE sha2_256_hexdigest(VALUE self, VALUE input) {
    // Convertir el valor Ruby a una cadena C
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input); // Obtener la longitud de la cadena
    unsigned char digest[SHA256_DIGEST_LENGTH]; // SHA-256 produce un hash de 32 bytes
    char out[65]; // 32 bytes * 2 para hexadecimal + 1 para el terminador

    // Calcular el hash SHA-256
    SHA256((unsigned char*)str, length, digest);

    // Convertir el hash a una cadena hexadecimal
    for (int n = 0; n < SHA256_DIGEST_LENGTH; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[64] = '\0'; // Terminar la cadena

    VALUE result = rb_str_new2(out); // Crear una nueva cadena Ruby
    return result;
}

VALUE sha2_384_hexdigest(VALUE self, VALUE input) {
    // Convertir el valor Ruby a una cadena C
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input); // Obtener la longitud de la cadena
    unsigned char digest[SHA384_DIGEST_LENGTH]; // SHA-384 produce un hash de 48 bytes
    char out[97]; // 48 bytes * 2 para hexadecimal + 1 para el terminador

    // Calcular el hash SHA-384
    SHA384((unsigned char*)str, length, digest);

    // Convertir el hash a una cadena hexadecimal
    for (int n = 0; n < SHA384_DIGEST_LENGTH; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[96] = '\0'; // Terminar la cadena

    VALUE result = rb_str_new2(out); // Crear una nueva cadena Ruby
    return result;
}

VALUE sha2_512_hexdigest(VALUE self, VALUE input) {
    // Convertir el valor Ruby a una cadena C
    char *str = RSTRING_PTR(input);
    int length = RSTRING_LEN(input); // Obtener la longitud de la cadena
    unsigned char digest[SHA512_DIGEST_LENGTH]; // SHA-512 produce un hash de 64 bytes
    char out[129]; // 64 bytes * 2 para hexadecimal + 1 para el terminador

    // Calcular el hash SHA-512
    SHA512((unsigned char*)str, length, digest);

    // Convertir el hash a una cadena hexadecimal
    for (int n = 0; n < SHA512_DIGEST_LENGTH; ++n) {
        sprintf(&(out[n * 2]), "%02x", (unsigned int)digest[n]);
    }
    out[128] = '\0'; // Terminar la cadena

    VALUE result = rb_str_new2(out); // Crear una nueva cadena Ruby
    return result;
}

VALUE sha3_224_hexdigest(VALUE self, VALUE input) {

    // Asegúrate de que el input es una cadena

    Check_Type(input, T_STRING);


    // Crear un contexto para el hash

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    const EVP_MD *md = EVP_sha3_224();

    

    // Inicializar el contexto y calcular el hash

    EVP_DigestInit_ex(ctx, md, NULL);

    EVP_DigestUpdate(ctx, (unsigned char *)StringValueCStr(input), RSTRING_LEN(input));

    

    unsigned char output[EVP_MAX_MD_SIZE];

    unsigned int output_len;


    EVP_DigestFinal_ex(ctx, output, &output_len);

    EVP_MD_CTX_free(ctx);


    // Convertir el hash a una cadena hexadecimal

    VALUE hex_string = rb_str_new("", 0);

    for (unsigned int i = 0; i < output_len; i++) {

        rb_str_catf(hex_string, "%02x", output[i]);

    }


    return hex_string;
}

VALUE sha3_256_hexdigest(VALUE self, VALUE input) {

    // Asegúrate de que el input es una cadena

    Check_Type(input, T_STRING);


    // Crear un contexto para el hash

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    const EVP_MD *md = EVP_sha3_256();

    

    // Inicializar el contexto y calcular el hash

    EVP_DigestInit_ex(ctx, md, NULL);

    EVP_DigestUpdate(ctx, (unsigned char *)StringValueCStr(input), RSTRING_LEN(input));

    

    unsigned char output[EVP_MAX_MD_SIZE];

    unsigned int output_len;


    EVP_DigestFinal_ex(ctx, output, &output_len);

    EVP_MD_CTX_free(ctx);
    // Convertir el hash a una cadena hexadecimal

    VALUE hex_string = rb_str_new("", 0);

    for (unsigned int i = 0; i < output_len; i++) {

        rb_str_catf(hex_string, "%02x", output[i]);

    }
    return hex_string;
}

VALUE sha3_384_hexdigest(VALUE self, VALUE input) {

    // Asegúrate de que el input es una cadena

    Check_Type(input, T_STRING);


    // Crear un contexto para el hash

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    const EVP_MD *md = EVP_sha3_384();

    

    // Inicializar el contexto y calcular el hash

    EVP_DigestInit_ex(ctx, md, NULL);

    EVP_DigestUpdate(ctx, (unsigned char *)StringValueCStr(input), RSTRING_LEN(input));

    

    unsigned char output[EVP_MAX_MD_SIZE];

    unsigned int output_len;


    EVP_DigestFinal_ex(ctx, output, &output_len);

    EVP_MD_CTX_free(ctx);


    // Convertir el hash a una cadena hexadecimal

    VALUE hex_string = rb_str_new("", 0);

    for (unsigned int i = 0; i < output_len; i++) {

        rb_str_catf(hex_string, "%02x", output[i]);

    }
    return hex_string;
}

VALUE sha3_512_hexdigest(VALUE self, VALUE input) {

    // Asegúrate de que el input es una cadena

    Check_Type(input, T_STRING);


    // Crear un contexto para el hash

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    const EVP_MD *md = EVP_sha3_512();

    

    // Inicializar el contexto y calcular el hash

    EVP_DigestInit_ex(ctx, md, NULL);

    EVP_DigestUpdate(ctx, (unsigned char *)StringValueCStr(input), RSTRING_LEN(input));

    

    unsigned char output[EVP_MAX_MD_SIZE];

    unsigned int output_len;


    EVP_DigestFinal_ex(ctx, output, &output_len);

    EVP_MD_CTX_free(ctx);


    // Convertir el hash a una cadena hexadecimal

    VALUE hex_string = rb_str_new("", 0);

    for (unsigned int i = 0; i < output_len; i++) {

        rb_str_catf(hex_string, "%02x", output[i]);

    }


    return hex_string;

}

void init_cobreak_openssl(){
                //Define module OpenSSL in mCoBreak
                mCoBreakOpenSSL = rb_define_module_under(mCoBreak, "OpenSSL");
                //Define Class MD5 encrypt mode
                cCoBreakOpenSSLhalf_md5 = rb_define_class_under(mCoBreakOpenSSL, "HALF_MD5", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLhalf_md5, "hexdigest", half_md5_hexdigest, 1);
                //Define Class SHA-1 encrypt mode
                cCoBreakOpenSSLsha1 = rb_define_class_under(mCoBreakOpenSSL, "SHA1", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha1, "hexdigest", sha1_hexdigest, 1);
                //Define Class SHA2-224 encrypt mode
                cCoBreakOpenSSLsha2_224 = rb_define_class_under(mCoBreakOpenSSL, "SHA2_224", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha2_224, "hexdigest", sha2_224_hexdigest, 1);
                //Define Class SHA2-256 encrypt mode
                cCoBreakOpenSSLsha2_256 = rb_define_class_under(mCoBreakOpenSSL, "SHA2_256", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha2_256, "hexdigest", sha2_256_hexdigest, 1);
                //Define Class SHA2-384 encrypt mode
                cCoBreakOpenSSLsha2_384 = rb_define_class_under(mCoBreakOpenSSL, "SHA2_384", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha2_384, "hexdigest", sha2_384_hexdigest, 1);
                //Define Class SHA2-512 encrypt mode
                cCoBreakOpenSSLsha2_512 = rb_define_class_under(mCoBreakOpenSSL, "SHA2_512", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha2_512, "hexdigest", sha2_512_hexdigest, 1);
                //Define Class SHA3-224 encrypt mode
                cCoBreakOpenSSLsha3_224 = rb_define_class_under(mCoBreakOpenSSL, "SHA3_224", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha3_224, "hexdigest", sha3_224_hexdigest, 1);
                //Define Class SHA3-224 encrypt mode
                cCoBreakOpenSSLsha3_256 = rb_define_class_under(mCoBreakOpenSSL, "SHA3_256", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha3_256, "hexdigest", sha3_256_hexdigest, 1);
                //Define Class SHA3-224 encrypt mode
                cCoBreakOpenSSLsha3_384 = rb_define_class_under(mCoBreakOpenSSL, "SHA3_384", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha3_384, "hexdigest", sha3_384_hexdigest, 1);
                //Define Class SHA3-224 encrypt mode
                cCoBreakOpenSSLsha3_512 = rb_define_class_under(mCoBreakOpenSSL, "SHA3_512", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha3_512, "hexdigest", sha3_512_hexdigest, 1);
                //Define Class RIPEMD-160 encrypt mode
                cCoBreakOpenSSLripemd160 = rb_define_class_under(mCoBreakOpenSSL, "RIPEMD_160", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLripemd160, "hexdigest", ripemd160_hexdigest, 1);
}
