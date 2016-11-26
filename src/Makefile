target:		r-ssh

OBJS=		main.o buffer.o socket.o transport.o trace.o types.o dh-keyexchange.o \
		exception.o random.o rsa-publickey.o keys.o algorithm.o cipher-aes.o \
		hmac-sha1.o
CXXFLAGS+=	-std=c++11 -g -I.. -fPIC
LDFLAGS+=	../cryptopp/libcryptopp.a
CXX=		clang
LINK=		g++

r-ssh:		$(OBJS)
		$(LINK) -o r-ssh $(OBJS) $(LDFLAGS)

clean:
		rm -f r-ssh $(OBJS)
