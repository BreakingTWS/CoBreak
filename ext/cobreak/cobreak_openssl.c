#include<cobreak_openssl.h>

VALUE mCoBreakOpenSSL;
VALUE cCoBreakOpenSSLmd4;
VALUE cCoBreakOpenSSLmd5;
VALUE cCoBreakOpenSSLsha1;
VALUE cCoBreakOpenSSLsha224;
VALUE cCoBreakOpenSSLsha256;
VALUE cCoBreakOpenSSLsha384;
VALUE cCoBreakOpenSSLsha512;
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

VALUE md4_hexdigest(VALUE self, VALUE full){
	char *str = RSTRING_PTR(full);
	int n;
	MD4_CTX c;
	unsigned char digest[16];
	char *out = (char*)malloc(33);
	int length = strlen(str);

    MD4_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD4_Update(&c, str, 512);
        } else {
            MD4_Update(&c, str, length);
        }
        length -= 512;
	str += 512;
    }

    MD4_Final(digest, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return rb_str_new2(out);
}

VALUE md5_hexdigest(VALUE self, VALUE full){
	char *str = RSTRING_PTR(full);
	int n;
	MD5_CTX c;
	unsigned char digest[16];
	char *out = (char*)malloc(33);
	int length = strlen(str);

    MD5_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
	str += 512;
    }

    MD5_Final(digest, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return rb_str_new2(out);
}

VALUE sha1_hexdigest(VALUE self, VALUE full){
	char *str = RSTRING_PTR(full);
	int n;
	SHA_CTX c;
	unsigned char digest[16];
	char *out = (char*)malloc(33);
	int length = strlen(str);

    SHA1_Init(&c);

    while (length > 0) {
        if (length > 512) {
            SHA1_Update(&c, str, 512);
        } else {
            SHA1_Update(&c, str, length);
        }
        length -= 512;
	str += 512;
    }

    SHA1_Final(digest, &c);

    for (n = 0; n < SHA_DIGEST_LENGTH; ++n) {
        snprintf(&(out[n*2]), SHA_DIGEST_LENGTH*2, "%02x", (unsigned int)digest[n]);
        //printf("%02", (unsigned int)digest[n]);
    }

    return rb_str_new2(out);
}

VALUE sha224_hexdigest(VALUE self, VALUE full){
	char *str = RSTRING_PTR(full);
	int n;
	SHA256_CTX c;
	unsigned char digest[65];
	char *out = (char*)malloc(64);
    out[64] = 0;
    int length = strlen(str);

    SHA224_Init(&c);

    while (length > 0) {
        if (length > 512) {
            SHA224_Update(&c, str, 512);
        } else {
            SHA224_Update(&c, str, length);
        }
        length -= 512;
	str += 512;
    }

    SHA224_Final(digest, &c);

    for (n = 0; n < SHA224_DIGEST_LENGTH; ++n) {
        snprintf(&(out[n*2]), SHA224_DIGEST_LENGTH*2, "%02x", (unsigned int)digest[n]);
        //printf("%02", (unsigned int)digest[n]);
    }

    return rb_str_new2(out);
    free(out);
}

VALUE sha256_hexdigest(VALUE self, VALUE full){
	char *str = RSTRING_PTR(full);
	int n;
	SHA256_CTX c;
	unsigned char digest[65];
	char *out = (char*)malloc(64);
    out[64] = 0;
    int length = strlen(str);

    SHA256_Init(&c);

    while (length > 0) {
        if (length > 512) {
            SHA256_Update(&c, str, 512);
        } else {
            SHA256_Update(&c, str, length);
        }
        length -= 512;
	str += 512;
    }

    SHA256_Final(digest, &c);

    for (n = 0; n < SHA256_DIGEST_LENGTH; ++n) {
        snprintf(&(out[n*2]), SHA256_DIGEST_LENGTH*2, "%02x", (unsigned int)digest[n]);
        //printf("%02", (unsigned int)digest[n]);
    }

    return rb_str_new2(out);
    free(out);
}

VALUE sha384_hexdigest(VALUE self, VALUE full){
	char *str = RSTRING_PTR(full);
	int n;
	SHA512_CTX c;
	unsigned char digest[65];
	char *out = (char*)malloc(64);
    out[64] = 0;
    int length = strlen(str);

    SHA384_Init(&c);

    while (length > 0) {
        if (length > 512) {
            SHA384_Update(&c, str, 512);
        } else {
            SHA384_Update(&c, str, length);
        }
        length -= 512;
	str += 512;
    }

    SHA384_Final(digest, &c);

    for (n = 0; n < SHA384_DIGEST_LENGTH; ++n) {
        snprintf(&(out[n*2]), SHA384_DIGEST_LENGTH*2, "%02x", (unsigned int)digest[n]);
        //printf("%02", (unsigned int)digest[n]);
    }

    return rb_str_new2(out);
    //free(out);
}

VALUE sha512_hexdigest(VALUE self, VALUE full){
	char *str = RSTRING_PTR(full);
	int n;
	SHA512_CTX c;
	unsigned char digest[65];
	char *out = (char*)malloc(64);
    out[64] = 0;
    int length = strlen(str);

    SHA512_Init(&c);

    while (length > 0) {
        if (length > 512) {
            SHA512_Update(&c, str, 512);
        } else {
            SHA512_Update(&c, str, length);
        }
        length -= 512;
	str += 512;
    }

    SHA512_Final(digest, &c);

    for (n = 0; n < SHA512_DIGEST_LENGTH; ++n) {
        snprintf(&(out[n*2]), SHA512_DIGEST_LENGTH*2, "%02x", (unsigned int)digest[n]);
        //printf("%02", (unsigned int)digest[n]);
    }

    return rb_str_new2(out);
    //free(out);
}

void init_cobreak_openssl(){
                mCoBreakOpenSSL = rb_define_module_under(mCoBreak, "OpenSSL");
                cCoBreakOpenSSLmd4 = rb_define_class_under(mCoBreakOpenSSL, "MD4", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLmd4, "hexdigest", md4_hexdigest, 1);
                cCoBreakOpenSSLmd5 = rb_define_class_under(mCoBreakOpenSSL, "MD5", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLmd5, "hexdigest", md5_hexdigest, 1);
                cCoBreakOpenSSLsha1 = rb_define_class_under(mCoBreakOpenSSL, "SHA1", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha1, "hexdigest", sha1_hexdigest, 1);
                cCoBreakOpenSSLsha224 = rb_define_class_under(mCoBreakOpenSSL, "SHA224", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha224, "hexdigest", sha224_hexdigest, 1);
                cCoBreakOpenSSLsha256 = rb_define_class_under(mCoBreakOpenSSL, "SHA256", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha256, "hexdigest", sha256_hexdigest, 1);
                cCoBreakOpenSSLsha384 = rb_define_class_under(mCoBreakOpenSSL, "SHA384", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha384, "hexdigest", sha384_hexdigest, 1);
                cCoBreakOpenSSLsha512 = rb_define_class_under(mCoBreakOpenSSL, "SHA512", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLsha512, "hexdigest", sha512_hexdigest, 1);
                cCoBreakOpenSSLripemd160 = rb_define_class_under(mCoBreakOpenSSL, "RIPEMD160", rb_cObject);
                rb_define_singleton_method(cCoBreakOpenSSLripemd160, "hexdigest", ripemd160_hexdigest, 1);

}
