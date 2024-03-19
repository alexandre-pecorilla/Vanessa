/*
    Vanessa 1.0 - Pour qu'elle planque ton chichon
    [i] Interactive CLI to encrypt shellcodes
    [!] Make sure `LaBouletteCestDansLaChaussette.dll` is in the same dir than Vanessa.exe
    alex@break.me
*/
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// [XOR function prototype]
typedef void (WINAPI* fnXORChaussette)(IN PBYTE, IN SIZE_T, IN PBYTE, IN SIZE_T);
fnXORChaussette XOR_CHAUSSETTE; // buffer for encrypted/decrypted shellcode passed by reference

// [RC4 function prototypes]
typedef struct // Required to repeat this for proto args
{
    unsigned int i;
    unsigned int j;
    unsigned char s[256];

} Rc4Context;

typedef void (WINAPI* fnRC4ChaussetteInit)(Rc4Context* context, const unsigned char* key, size_t length);
fnRC4ChaussetteInit RC4_CHAUSSETTE_INIT;

typedef void (WINAPI* fnRC4Chaussette)(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length);
fnRC4Chaussette RC4_CHAUSSETTE; // returns a pointer with encrypted/decrypted shellcode


/*
    [i] Loads the encryption librairie at runtime & exports the functions 
*/
void loadChaussettes() {
    // Get DLL handle
    HMODULE hModule = GetModuleHandleA("LaBouletteCestDansLaChaussette.dll");
    if (hModule == NULL) {
        hModule = LoadLibraryA("LaBouletteCestDansLaChaussette.dll");
        if (hModule == NULL) {
            printf("Failed to load the DLL\n");
            return;
        }
    }

    // Get function addresses

    // XOR
    PVOID pXORChaussette = GetProcAddress(hModule, "XORChaussette");
    if (pXORChaussette == NULL) {
        printf("Failed to find the XORChaussette function\n");
        return;
    }

    // RC4
    PVOID pRc4ChaussetteInit = GetProcAddress(hModule, "rc4Init");
    if (pRc4ChaussetteInit == NULL) {
        printf("Failed to find the RC4ChaussetteInit function\n");
        return;
    }

    PVOID pRc4Chaussette = GetProcAddress(hModule, "rc4Cipher");
    if (pRc4Chaussette == NULL) {
        printf("Failed to find the RC4Chaussette function\n");
        return;
    }


    // Cast functions
    XOR_CHAUSSETTE = (fnXORChaussette)pXORChaussette;
    RC4_CHAUSSETTE_INIT = (fnRC4ChaussetteInit)pRc4ChaussetteInit;
    RC4_CHAUSSETTE = (fnRC4Chaussette)pRc4Chaussette;

    // [i] Functions are now ready to be called in main like XOR_CHAUSSETTE(...)
}

/*
    [i] Prints chichon as raw hexadecimal or C code
    [!] Fully AI-generated
*/
void printChichon(IN PBYTE pChichon, IN SIZE_T sChichon, BOOL raw) {

    printf("\n");
    if (raw == TRUE) { // Print raw
        for (size_t i = 0; i < sChichon; i++) {
            printf("%02X ", pChichon[i]); // Print each byte in hex format
        }
    }
    else { // Print C
        printf("unsigned char chichon[] = {");
        for (size_t i = 0; i < sChichon; i++) {
            printf("0x%02X", pChichon[i]); // Print each byte in hex format suitable for C code
            if (i < sChichon - 1) {
                printf(", "); // Add a comma between bytes but not after the last one
            }
        }
        printf("};");
    }
    printf("\n");
}

/*
    [i] Reads a file byte by byte and saves it into an unsigned char*
    [!] Needs buffer size as SIZE_T and returns the pointer to the byte array
    [!] Partially AI-generated
*/
unsigned char* readFileByteByByte(const char* filename, size_t* bufferSize) {
    FILE* file;
    unsigned char* buffer;
    size_t fileSize;
    size_t result;
    errno_t err;

    // Open the file in binary mode using fopen_s
    err = fopen_s(&file, filename, "rb");
    if (err != 0 || file == NULL) {
        perror("Error opening file");
        return NULL;
    }

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    rewind(file); // Go back to the start of the file

    // Allocate memory for the entire file
    buffer = (unsigned char*)malloc(sizeof(unsigned char) * fileSize);
    if (buffer == NULL) {
        perror("Memory error");
        fclose(file);
        return NULL;
    }

    // Read the file into the buffer
    result = fread(buffer, 1, fileSize, file);
    if (result != fileSize) {
        perror("Reading error");
        free(buffer);
        fclose(file);
        return NULL;
    }

    // Close the file
    fclose(file);

    // Set the buffer size
    *bufferSize = fileSize;

    // Return the buffer containing the file
    return buffer;
}

/*
    [i] Save a byte array into a file, byte after byte
    [!] Partially AI-generated
*/
int saveBytesToFile(const char* filename, const unsigned char* data, size_t dataSize) {
    FILE* file;
    errno_t err;

    // Open the file in binary mode using fopen_s
    err = fopen_s(&file, filename, "wb");
    if (err != 0 || file == NULL) {
        perror("Error opening file");
        return -1; // Return error code
    }

    // Write the array of bytes to the file
    size_t written = fwrite(data, sizeof(unsigned char), dataSize, file);
    if (written != dataSize) {
        perror("Error writing to file");
        fclose(file);
        return -1; // Return error code
    }

    // Close the file
    fclose(file);
    return 0; // Success
}

/*
    [i] Clear the input of getchar() of the \n
    [!] Fully AI-generated
*/
void clearInputBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}


/*
    [i] Encrypts shellcode using RC4
    [i] Uses functions of LaBouletteCestDansLaChaussette.dll
    [i] Returns a pointer!

    chichon: shellcode
    sChichon: Size of shellcode
    key: Encryption key
    sKey: Size of key

    Example usage: rc4Enc(chichon, sizeof(chichon), key, sizeof(key));
*/
unsigned char* rc4Enc(unsigned char* chichon, SIZE_T sChichon, unsigned char* key, SIZE_T sKey) {
    Rc4Context ctx = { 0 };
    RC4_CHAUSSETTE_INIT(&ctx, key, sKey); // Initialize RC4 context with the key
    unsigned char* cipherChichon = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sChichon); // Allocate memory for the encrypted data
    RC4_CHAUSSETTE(&ctx, chichon, cipherChichon, sChichon); // Encrypt the shellcode
    return cipherChichon;
}

/*
    [i] Decrypts shellcode using RC4
    [i] Uses functions of LaBouletteCestDansLaChaussette.dll
    [i] Returns a pointer!

    Cipherchichon: RC4 encrypted shellcode
    sCipherChichon: Size of RC4 encrypted shellcode
    key: Encryption key
    sKey: Size of key

    Example usage: rc4Enc(chichon, sizeof(chichon), key, sizeof(key));
*/
unsigned char* rc4Dec(unsigned char* cipherChichon, SIZE_T sCipherChichon, unsigned char* key, SIZE_T sKey) {
    Rc4Context ctx = { 0 };
    RC4_CHAUSSETTE_INIT(&ctx, key, sKey); // Initialize RC4 context with the key
    unsigned char* clearChichon = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sCipherChichon); // Allocate memory for the encrypted data
    RC4_CHAUSSETTE(&ctx, cipherChichon, clearChichon, sCipherChichon); // Encrypt the shellcode
    return clearChichon;
}

int main(int argc, char* argv[]) {

    // Credits
    printf("Vanessa v1.0 - alex@break.me\nPour qu'elle planque ton chichon...\n\n");

    // Validate argument count
    if (argc != 4) {
        printf("Vanessa 1.1 Usage Guide\n\n"
            "Basic Commands:\n\n"
            "    Encrypt with XOR: Vanessa.exe ex input.bin key\n"
            "    Decrypt with XOR: Vanessa.exe dx input.bin key\n"
            "    Encrypt with RC4: Vanessa.exe er input.bin key\n"
            "    Decrypt with RC4: Vanessa.exe dr input.bin key\n\n"
            "Output Formats:\n\n"
            "    Add 'b' for binary data saved into a file (e.g., Vanessa.exe exb input.bin key)\n"
            "    Add 'c' for C/C++ array output to copy into your code (e.g., Vanessa.exe exc input.bin key)\n\n"
            "Notes:\n\n"
            "    'input.bin' must be a file containing binary data, e.g., generated with msfvenom -f raw.\n"
            "    'key' should be a string used as the password for encryption/decryption.\n");
        return 1;
    }

    // Load encrytption functions from LaBouletteCestDansLaChaussette.dll
    loadChaussettes();

    // Open the file
    size_t size;
    unsigned char* chichon = readFileByteByByte(argv[2], &size);

    // Fetch & cast the key
    unsigned char* key = (unsigned char*)argv[3];
    SIZE_T sKey = strlen(argv[3]);
    
    // Print raw shellcode
    printf("-------- Original Chichon --------\n");
    printChichon(chichon, size, TRUE);

    // Prepare RC4 buffers for encrypted & decrypted shellcodes (not needeed for XOR who is passed by reference)
    unsigned char* cipherChichon = NULL;
    unsigned char* clearChichon;

    // ENCRYPTION

    if (argv[1][0] == 'e') {

        // XOR
        if (argv[1][1] == 'x') {
            // Encrypt
            XOR_CHAUSSETTE(chichon, size, key, sKey);
            // Print encrypted shellcode
            printf("\n-------- >> XOR Encrypted Chichon << --------\n");
            printChichon(chichon, size, TRUE);

        }
        // RC4
        else if (argv[1][1] == 'r') {
            // Encrypt
            cipherChichon = rc4Enc(chichon, size, key, sKey);
            // Print encrypted shellcode
            printf("\n-------- >> RC4 Encrypted Chichon << --------\n");
            printChichon(cipherChichon, size, TRUE);
            // Copy since its not passed by reference (needed for rest of main)
            memcpy(chichon, cipherChichon, size);
        }
        // Keep this case for when you only want to display the shellcode in hex
        else {
            return 0;
        }

    // DECRYPTION

    } else if(argv[1][0] == 'd') {

        // XOR
        if (argv[1][1] == 'x') {
            // Decrypt
            XOR_CHAUSSETTE(chichon, size, key, sKey);
            // Print decrypted shellcode
            printf("\n-------- >> XOR Decrypted Chichon << --------\n");
            printChichon(chichon, size, TRUE);
        }
        // RC4
        else if (argv[1][1] == 'r') {
            // Decrypt
            clearChichon = rc4Dec(chichon, size, key, sKey);
            // Print decrypted shellcode
            printf("\n-------- >> RC4 Decrypted Chichon << --------\n");
            printChichon(clearChichon, size, TRUE);
            // Copy since its not passed by reference (needed for rest of main)
            memcpy(chichon, clearChichon, size);
        }
        // Keep this case for when you only want to display the shellcode in hex
        else {
            return 0;
        }
    }

    // OUTPUT FORMAT

    // Binary file
    if (argv[1][2] == 'b') {
        saveBytesToFile("boulette.bin", chichon, size);
        printf("\nBinary data saved into file >> boulette.bin <<\n");
    }
    // C/CPP code
    else if (argv[1][2] == 'c') {
        printf("\nCopy this C/C++ code into your stager:\n");
        printChichon(chichon, size, FALSE);
    }
    else {
        return 0;
    }
    return 0;
}
