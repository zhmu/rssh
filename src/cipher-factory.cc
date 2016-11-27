#include "cipher-factory.h"
#include <string.h>
#include "cipher-aes.h"

namespace RSSH {

namespace CipherFactory {

ICipher* Create(const char* cipherName, bool encrypt, const uint8_t* iv, const uint8_t* key)
{
	if (strcmp(cipherName, "aes128-cbc") == 0)
		if (encrypt)
			return new Cipher_AES_128_CBC_Encrypt(iv, key);
		else
			return new Cipher_AES_128_CBC_Decrypt(iv, key);

	return NULL;
}


} // namespace CipherFactory

} // namespace RSSH
