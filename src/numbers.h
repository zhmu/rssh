#ifndef RSSH_NUMBERS_H
#define RSSH_NUMBERS_H

#include <stdint.h>

namespace RSSH {
namespace Numbers {

static const char* ourGreeter = "SSH-2.0-rssh_0.1";

/*
 * This is basically a translation of RFC 4250 - The Secure Shell (SSH)
 * Protocol Assigned Numbers. All references are to this RFC.
 */

// 4.1 Message Numbers
enum class MessageID : uint8_t {
	/* Transport */
	SSH_MSG_DISCONNECT = 1,
	SSH_MSG_IGNORE = 2,
	SSH_MSG_UNIMPLEMENTED = 3,
	SSH_MSG_DEBUG = 4,
	SSH_MSG_SERVICE_REQUEST = 5,
	SSH_MSG_SERVICE_ACCEPT = 6,
	SSH_MSG_KEXINIT = 20,
	SSH_MSG_NEWKEYS = 21,
	SSH_MSG_KEXDH_INIT = 30,
	SSH_MSG_KEXDH_REPLY = 31,
	/* User authentication */
	SSH_MSG_USERAUTH_REQUEST = 50,
	SSH_MSG_USERAUTH_FAILURE = 51,
	SSH_MSG_USERAUTH_SUCCESS = 52,
	SSH_MSG_USERAUTH_BANNER = 53,
	SSH_MSG_USERAUTH_INFO_REQUEST = 60, // [KBD-INT]
	SSH_MSG_USERAUTH_INFO_RESPONSE = 61, // [KBD-INT]
	/* Connect */
	SSH_MSG_GLOBAL_REQUEST = 80,
	SSH_MSG_REQUEST_SUCCESS = 81,
	SSH_MSG_REQUEST_FAILURE = 82,
	SSH_MSG_CHANNEL_OPEN = 90,
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
	SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
	SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
	SSH_MSG_CHANNEL_DATA = 94,
	SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
	SSH_MSG_CHANNEL_EOF = 96,
	SSH_MSG_CHANNEL_CLOSE = 97,
	SSH_MSG_CHANNEL_REQUEST = 98,
	SSH_MSG_CHANNEL_SUCCESS = 99,
	SSH_MSG_CHANNEL_FAILURE = 100,
};

// 4.2 Disconnection Messages Reason Codes and Descriptions
enum class DisconnectReason : uint8_t {
	SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
	SSH_DISCONNECT_PROTOCOL_ERROR = 2,
	SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
	SSH_DISCONNECT_RESERVED = 4,
	SSH_DISCONNECT_MAC_ERROR = 5,
	SSH_DISCONNECT_COMPRESSION_ERROR = 6,
	SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
	SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
	SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
	SSH_DISCONNECT_CONNECTION_LOST = 10,
	SSH_DISCONNECT_BY_APPLICATION = 11,
	SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
	SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
	SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
	SSH_DISCONNECT_ILLEGAL_USER_NAME = 15,
};

// 4.3 Channel Connection Failure Reason Codes and Descriptions
enum class ChannelReason : uint8_t {
	SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
	SSH_OPEN_CONNECT_FAILED = 2,
	SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
	SSH_OPEN_RESOURCE_SHORTAGE = 4,
};

// 4.4 Extended Channel Data Transfer data_type_code and Data
enum class ExtendedChannelDataType : uint32_t {
	SSH_EXTENDED_DATA_STDERR = 1,
};

// 4.5 Pseudo-Terminal Encoded Terminal Modes
#if 0
enum class PseudoTerminalMode : uint8_t {
	TTY_OP_END = 0,
	VINTR = 1,
	VQUIT = 2,
	VERASE = 3,
	VKILL = 4,
	VEOF = 5,
	VEOL = 6,
	VEOL2 = 7,
	VSTART = 8,
	VSTOP = 9,
	VSUSP = 10,
	VDSUSP = 11,
	VREPRINT = 12,
	VWERASE = 13,
	VLNEXT = 14,
	VFLUSH = 15,
	VSWTCH = 16,
	VSTATUS = 17,
	VDISCARD = 18,
	IGNPAR = 30,
	PARMRK = 31,
	INPCK = 32,
	ISTRIP = 33,
	INLCR = 34,
	IGNCR = 35,
	ICRNL = 36,
	IUCLC = 37,
	IXON = 38,
	IXANY = 39,
	IXOFF = 40,
	IMAXBEL = 41,
	ISIG = 50,
	ICANON = 51,
	XCASE = 52,
	ECHO = 53,
	ECHOE = 54,
	ECHOK = 55,
	ECHONL = 56,
	NOFLSH = 57,
	TOSTOP = 58,
	IEXTEN = 59,
	ECHOCTL = 60,
	ECHOKE = 61,
	PENDIN = 62,
	OPOST = 70,
	OLCUC = 71,
	ONLCR = 72,
	OCRNL = 73,
	ONOCR = 74,
	ONLRET = 75,
	CS7 = 90,
	CS8 = 91,
	PARENB = 92,
	PARODD = 93,
	TTY_OP_ISPEED = 128,
	TTY_OP_OSPEED = 129,
};
#endif

// 4.7 Service Names
namespace ServiceNames {
	static const char* UserAuth = "ssh-userauth";
	static const char* Connection = "ssh-connection";
};

// 4.8 Authentication Method Names
namespace AuthenticationMethodNames {
	static const char* PublicKey = "publickey";
	static const char* Password = "password";
	static const char* HostBased = "hostbased";
	static const char* KeyboardInteractive = "keyboard-interactive"; // As specified in [KBD-INT]
	static const char* None = "none";
};

// 4.9 Connection Protocol Assigned Names
namespace ConnectionProtocolAssignedNames {
	// 4.9.1 Connection Protocol Channel Types
	namespace ChannelTypes {
		static const char* Session = "session";
		static const char* X11 = "x11";
		static const char* ForwardedTcpIp = "forwarded-tcpip";
		static const char* DirectTcpIp = "direct-tcpip";
	}

	// 4.9.2 Connection Protocol Global Request Names
	namespace RequestType {
		static const char* TcpIpForward = "tcpip-forward";
		static const char* CancelTcpIpForward = "cancel-tcpip-forward";
	};

	// 4.9.3 Connection Protocol Channel Request Names
	namespace RequestType {
		static const char* PtyReq = "pty-req";
		static const char* X11Req = "x11-req";
		static const char* Env = "env";
		static const char* Shell = "shell";
		static const char* Exec = "exec";
		static const char* SubSystem = "subsystem";
		static const char* WindowChange = "window-change";
		static const char* XonXoff = "xon-xoff";
		static const char* Signal = "signal";
		static const char* ExitStatus = "exit-status";
		static const char* ExitSignal = "exit-signal";
	};

	// 4.9.4 Initial Assignment of Signal Names (?)
};

// 4.11 Assigned Algorithm Names
namespace AlgorithmNames {
	// 4.11.1 Encryption Algorithm Names
	namespace Encryption {
		static const char* TripleDESCbc = "3des-cbc";
		static const char* BlowFishCBC = "blowfish-cbc";
		static const char* TwoFish256CBC = "twofish256-cbc";
		static const char* TwoFishCBC = "twofish-cbc";
		static const char* TwoFish192CBC = "twofish192-cbc";
		static const char* TwoFish128CBC= "twofish128-cbc";
		static const char* AES256CBC = "aes256-cbc";
		static const char* AES192CBC= "aes192-cbc";
		static const char* AES128CBC = "aes128-cbc";
		static const char* Serpent256CBC = "serpent256-cbc";
		static const char* Serpent192CBC = "serpent192-cbc";
		static const char* Serpent128CBC = "serpent128-cbc";
		static const char* ArcFour = "arcfour";
		static const char* IDEACBC = "idea-cbc";
		static const char* CAST128CBC = "cast128-cbc";
		static const char* None = "none";
		static const char* DesCBC = "des-cbc";
	}

	// 4.11.2 MAC Algorithm Names
	namespace MAC {
		static const char* HMAC_SHA1 = "hmac-sha1";
		static const char* HMAC_SHA1_96 = "hmac-sha1-96";
		static const char* HMAC_MD5 = "hmac-md5";
		static const char* HMAC_MD5_96 = "hmac-md5-96";
		static const char* None = "none";
	}

	// 4.11.3 Public Key Algorithm Names
	namespace PublicKey {
		static const char* SSH_DSS = "ssh-dss";
		static const char* SSH_RSA = "ssh-rsa";
		static const char* PGP_Sign_RSA = "pgp-sign-rsa";
		static const char* PGP_Sign_DSS = "pgp-sign-dss";
	}

	// 4.11.4 Compression Algorithm Names
	namespace Compression {
		static const char* None = "none";
		static const char* ZLIB = "zlib";
	}
}

} // namespace Numbers
} // namespace RSSH

#endif /* RSSH_NUMBERS_H */
