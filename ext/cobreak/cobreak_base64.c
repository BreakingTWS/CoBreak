#include<cobreak_base64.h>
#include<cobreak_ruby.h>

char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

VALUE cCoBreakBase64;

void decodeblock(unsigned char in[], char *clrstr) {
	unsigned char out[4];
	out[0] = in[0] << 2 | in[1] >> 4;
	out[1] = in[1] << 4 | in[2] >> 2;
	out[2] = in[2] << 6 | in[3] >> 0;
	out[3] = '\0';
	strncat(clrstr, out, sizeof(out));
}

VALUE b64_decode(VALUE self, VALUE full){
//	check_Type(full, T_STRING);
	int c, phase, i;
	unsigned char in[4];
	char *p;

	char *myb64 = RSTRING_PTR(full);
	char strb64[1024] = "";
	char *clrdst = strb64;
	clrdst[0] = '\0';
	phase = 0; i=0;
	while(myb64[i]){
		c = (int) myb64[i];
		if(c == '='){
			decodeblock(in, clrdst);
			break;
		}
		p = strchr(b64, c);
		if(p){
			in[phase] = p - b64;
			phase = (phase + 1) % 4;
			if(phase == 0){
				decodeblock(in, clrdst);
				in[0]=in[1]=in[2]=in[3]=0;
			}
		}
		i++;
	}
	return rb_str_new2(strb64);
}

void encodeblock(unsigned char bl[], char b64str[], int len){
	unsigned char out[5];
	out[0] = b64[ bl[0] >> 2 ];
	out[1] = b64[ ((bl[0] & 0x03) << 4) | ((bl[1] & 0xf0) >> 4) ];
	out[2] = (unsigned char) (len > 1 ? b64[ ((bl[1] & 0x0f) << 2) | ((bl[2] & 0xc0) >> 6) ] : '=');
	out[3] = (unsigned char) (len > 2 ? b64[ bl[2] & 0x3f ] : '=');
	out[4] = '\0';
	strncat(b64str, out, sizeof(out));
}

VALUE b64_encode(VALUE self, VALUE full){
//	check_Type(full, T_STRING);
	unsigned char in[3];
	int i, len = 0;
	int j = 0;
	//char b64dst[1024];
	char *strb64 = RSTRING_PTR(full);
	char myb64[1024] = "";
	char *b64dst = myb64;
	b64dst[0] = '\0';
	while(strb64[j]){
		len = 0;
		for(i=0; i<3; i++){
			in[i] = (unsigned char) strb64[j];
			if(strb64[j]) {
				len++; j++;
			}
			else in[i] = 0;
		}
		if(len){
			encodeblock(in, b64dst, len);
		}
	}
	return rb_str_new2(b64dst);
}

void init_cobreak_base64(){
	cCoBreakBase64 = rb_define_class_under(mCoBreak, "Base64", rb_cObject);

	rb_define_singleton_method(cCoBreakBase64, "encode", b64_encode, 1);
	rb_define_singleton_method(cCoBreakBase64, "decode", b64_decode, 1);
}
