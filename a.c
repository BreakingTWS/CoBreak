#include <stdio.h>
#include <gcrypt.h>

int main(){
	gcry_md_hd_t handle; // Declaración del handle
	gcry_error_t err = gcry_md_open(&handle, GCRY_MD_SHAKE128, 0);
		if (err) {
			printf("Error");
    		
		}
	return 0;
}
