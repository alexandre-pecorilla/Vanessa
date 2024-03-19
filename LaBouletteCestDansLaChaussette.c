/*
    LaBouletteCestDansLaChaussette 1.0 - Pour planquer le chichon
    [i] Encryption librairie used by Vanessa - Can also be used standalone
    [!] For now it only supports XOR encryption
    alex@break.me
*/
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/*
	>>> XOR ENCRYPTION / DECRYPTION <<<

	[i] We use a function from Maldev Academy

	- pChichon : Pointer to shellcode
	- sChichon : Shellcode size
	- bKey : Encryption key given as an array of bytes (e.g. unsigned char bKey[] = {'S', 'e', 'C', 'r', 'E', 'T'};)
	- sKey : Key size

	Example call: XORChaussette(shellcode, sizeof(shellcode), key, sizeof(key));
*/
extern __declspec(dllexport) VOID XORChaussette(IN PBYTE pChichon, IN SIZE_T sChichon, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sChichon; i++, j++) {
		if (j >= sKeySize) {
			j = 0;
		}
		pChichon[i] = pChichon[i] ^ bKey[j];
	}
}

/* 
    >>> RC4 ENCRYPTION / DECRYPTION <<<

	[i] We use an existing C library -> https://www.oryx-embedded.com/doc/rc4_8c_source.html

	Encryption example:

	// Initialization
	Rc4Context ctx = { 0 };

	// Key used for encryption
	unsigned char* key = "maldev123";
	rc4Init(&ctx, key, strlen(key));

	// Encryption //
	// plaintext - The payload to be encrypted
	// ciphertext - A buffer that is used to store the outputted encrypted data
	rc4Cipher(&ctx, plaintext, ciphertext, sizeof(plaintext));

	Decryption example:

	// Initialization
	Rc4Context ctx = { 0 };

	// Key used to decrypt
	unsigned char* key = "maldev123";
	rc4Init(&ctx, key, strlen(key));

	// Decryption //
	// ciphertext - Encrypted payload to be decrypted
	// plaintext - A buffer that is used to store the outputted plaintext data
	rc4Cipher(&ctx, ciphertext, plaintext, sizeof(ciphertext));

*/
typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;


extern __declspec(dllexport) void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		j = (j + context->s[i] + key[i % length]) % 256;

		//Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}


extern __declspec(dllexport) void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// Valid input and output?
		if (input != NULL && output != NULL)
		{
			//XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			//Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
}
