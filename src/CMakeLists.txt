add_executable(r-ssh algorithm.cc buffer.cc cipher-aes.cc dh-keyexchange.cc exception.cc hmac-sha1.cc keys.cc main.cc random.cc rsa-publickey.cc socket.cc trace.cc transport.cc types.cc)
target_link_libraries(r-ssh cryptopp)
include_directories(..)
