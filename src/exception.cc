#include "exception.h"

namespace RSSH {

const char* Exception::what() const noexcept
{
	switch(m_Code) {
		case C_Buffer_Too_Short:
			return "attempt to seek to a wrong buffer offset";
		case C_Buffer_Out_Of_Data:
			return "not enough data in buffer";
		case C_Buffer_Full:
			return "buffer full";
		case C_DH_Unrecognized_Algorithm:
			return "unrecognized DH algorithm";
		case C_PK_Unrecognized_Algorithm:
			return "unrecognized public key algorithm";
		case C_PK_Signature_Mismatch:
			return "invalid public key signature";
		case C_HMAC_Mismatch:
			return "HMAC integrity failure";
		case C_Socket_Error:
			return "socket I/O error";
		case C_Transport_Greeter_Corrupt:
			return "received corrupt greeter";
		case C_Transport_Invalid_Length:
			return "invalid length received";
		case C_Transport_Version_Mismatch:
			return "version mismatch";
	}
	return "?";
}

} // namespace RSSH
