#ifndef RSSH_EXCEPTION_H
#define RSSH_EXCEPTION_H

#include <stdexcept>
#include <string>

namespace RSSH {

class Exception : public std::exception {
public:
	enum Code {
		C_Buffer_Too_Short,
		C_Buffer_Out_Of_Data,
		C_Buffer_Full,
		C_PK_Unrecognized_Algorithm,
		C_DH_Unrecognized_Algorithm,
		C_PK_Signature_Mismatch,
		C_HMAC_Mismatch,
		C_Socket_Error,
		C_Transport_Greeter_Corrupt,
		C_Transport_Version_Mismatch,
		C_Transport_Invalid_Length,
		C_HostKey_Signature_Rejected,
	};

	Exception(Code code, const char* param = "")
	 : m_Code(code), m_Param(param) {
	}
	const Code& GetCode() const noexcept {
		return m_Code;
	}
	virtual const char* what() const noexcept;
	const std::string& GetParameter() const {
		return m_Param;
	}

private:
	std::string m_Param;
	Code m_Code;
};

} // namespace RSSH

#endif /* RSSH_EXCEPTION_H */
