#include<cobreak_ruby.h>

#define MAX_LINE_LENGTH 256
#define BLOCK_SIZE 1024

// Define el módulo y la clase
VALUE mCoBreakAttackCipher;
VALUE cCoBreakAttackCipherCesar;

// Función para cifrar con el cifrado César
void decodeblock_attack_cesar(const char *input, char *output, int shift) {
    for (size_t i = 0; i < strlen(input); i++) {
        char c = input[i];
        if (c >= 'A' && c <= 'Z') {
            output[i] = (c - 'A' - shift + 26) % 26 + 'A'; // Ajuste para evitar negativos
        } else if (c >= 'a' && c <= 'z') {
            output[i] = (c - 'a' - shift + 26) % 26 + 'a'; // Ajuste para evitar negativos
        } else {
            output[i] = c; // No descifrar caracteres no alfabéticos
        }
    }
    output[strlen(input)] = '\0'; // Asegurarse de que la cadena de salida esté terminada
}

// Función para realizar el ataque de diccionario César
VALUE attackwordlist_cesar(VALUE self, VALUE text, VALUE dictionary) {
    FILE *archivo = fopen(StringValueCStr(dictionary), "r");
    if (archivo == NULL) {
        rb_raise(rb_eIOError, "Error al abrir el archivo de texto");
    }

    VALUE result_array = rb_ary_new(); // Array para almacenar resultados
    char *linea = malloc(MAX_LINE_LENGTH * sizeof(char));
    if (linea == NULL) {
        fclose(archivo);
        rb_raise(rb_eRuntimeError, "Error de asignación de memoria");
    }

    while (fgets(linea, MAX_LINE_LENGTH, archivo)) {
        linea[strcspn(linea, "\r\n")] = 0; // Eliminar el salto de línea

        // Convertir la línea a un número (asumimos que la línea contiene un número)
        int shift = atoi(linea);
        char output[1024]; // Buffer para la salida

        // Cifrar el texto con el desplazamiento encontrado
        decodeblock_attack_cesar(StringValueCStr(text), output, shift);

        // Agregar el resultado al array
        rb_ary_push(result_array, rb_str_new_cstr(output));
    }

    free(linea);
    fclose(archivo);

    return result_array; // Devolver el array de resultados
}

// Inicialización del módulo y la clase
int init_cobreak_attack_cipherw() 
    // Define el módulo Cipher en mCoBreak
    mCoBreakAttackCipher = rb_define_module_under(mCoBreak, "CipherAttack");

    // Define la clase Cesar attack
    cCoBreakAttackCipherCesar = rb_define_class_under(mCoBreakAttackCipher, "Cesar", rb_cObject);

    // Define el método para la clase Cesar
    rb_define_singleton_method(cCoBreakAttackCipherCesar, "crack", attackwordlist_cesar, 2);

}