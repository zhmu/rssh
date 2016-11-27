#ifndef RSSH_CIPHER_FACTOR_H
#define RSSH_CIPHER_FACTOR_H

#include <stdint.h>

namespace RSSH {

class ICipher;

namespace CipherFactory {

ICipher* Create(const char* cipherName, bool encrypt, const uint8_t* iv, const uint8_t* key);

} // namespace CipherFactory

} // namespace RSSH

#endif /* RSSH_CIPHER_FACTOR_H */
