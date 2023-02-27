all: build-server build-client run

build-server:
	gcc -o server rpc_server.c auth_svc.c auth_xdr.c -lnsl

build-client:
	gcc -o client rpc_client.c auth_clnt.c auth_xdr.c -lnsl

run:
	./check.sh all

clean:
	rm -f client server client.out server.out
