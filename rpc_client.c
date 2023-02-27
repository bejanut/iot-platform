#include <stdio.h>
#include <rpc/rpc.h> 

#include "auth.h"

typedef struct ClientData {
    char *uid;
    char *accessToken;
    char *refreshToken;
    int usesLeft;
} ClientData;

ClientData **clientData;
int clientsCount = 0;
int clientSize = 20;

void initClient() {
    clientData = calloc(clientSize, sizeof(ClientData *));
}

int translateAction(char *action) {
    if (!strcmp(action, "REQUEST")) return REQUEST;
    if (!strcmp(action, "READ")) return READ;
    if (!strcmp(action, "INSERT")) return INSERT;
    if (!strcmp(action, "MODIFY")) return MODIFY;
    if (!strcmp(action, "DELETE")) return DELETE;
    if (!strcmp(action, "EXECUTE")) return EXECUTE;

    return -1;
}

// Functions to manipulate the client data structures
int getUserIdPosClient(char *uid) {
    for (int i = 0; i < clientsCount; i++) {
        if (!strcmp(clientData[i]->uid, uid)) {
            return i;
        }
    }

    return -1;
}
int getUserPosFromAuthTokenClient(char *token) {
    for (int i = 0; i < clientsCount; i++) {
        char *curToken = clientData[i]->accessToken;
        if (curToken != NULL && !strcmp(curToken, token)) {
            return i;
        }
    }

    return -1;
}
void updateClientData(char *uid, Auth_Response *res) {
    int userPos = getUserIdPosClient(uid);
    
    if (userPos == -1) {
        ClientData *data;
        data = calloc(1, sizeof(ClientData));
        
        data->uid = strdup(uid);
        data->accessToken = res->accessToken;
        data->refreshToken = strcmp(res->refreshToken, "\0") ?  res->refreshToken : NULL;
        data->usesLeft = res->expiry;

        if (clientsCount >= clientSize) {
            clientSize *= 2;
            clientData = realloc(clientData, clientSize * sizeof(ClientData*));
        }

        clientData[clientsCount] = data;
        clientsCount++;
    } else {
        clientData[userPos]->accessToken = res->accessToken;
        clientData[userPos]->refreshToken = strcmp(res->refreshToken, "\0") ? res->refreshToken : NULL;
        clientData[userPos]->usesLeft = res->expiry;
    }
}


void translateClientRequests(char *file, CLIENT *cl) {
    int bufferLen = 500;
    char buffer[500];

    FILE *f = fopen(file, "r");
    if (f == NULL) {
        printf("Error opening %s\n", file);
    }

    while (fgets(buffer, bufferLen, f)) {  
        char *uid = strdup(strtok(buffer, ",\n"));
        char *action = strdup(strtok(NULL, ",\n"));
        char *resource = strdup(strtok(NULL, ",\n"));

        if (!strcmp(action, "REQUEST")) {
            char **requestToken = request_authorization_1(&uid, cl);

            if (!strcmp(*requestToken, "\0")) {
                printf("USER_NOT_FOUND\n");

                continue;
            }

            char **signedToken = approve_request_token_1(requestToken, cl);
            Auth_Request *req = malloc(sizeof(Auth_Request));
            req->requestToken = strdup(*signedToken);
            req->shouldRefresh = atoi(resource);
            Auth_Response *res = request_access_token_1(req, cl);

            if (res->status == REQUEST_DENIED) {
                printf("REQUEST_DENIED\n");
            } else {
                updateClientData(uid, res);
                printf("%s -> %s", *requestToken, res->accessToken);
				if (!strcmp(res->refreshToken, "\0")) {
					printf("\n");
				} else {
					printf(",%s\n", res->refreshToken);
				}
            }
        } else {
            int pos = getUserIdPosClient(uid);
            Action_Request *req = malloc(sizeof(Action_Request));

            req->resource = resource;
            req->action = action;

            // Check if there is a saved acces token for the provided uid
            if (pos == -1) {
                req->accessToken = strdup("\0");
            } else {
                if (clientData[pos]->usesLeft == 0 && clientData[pos]->refreshToken != NULL) {
                    char *refreshToken = clientData[pos]->refreshToken;
                    Auth_Response *res = refresh_access_token_1(&refreshToken, cl);
                    updateClientData(uid, res);
                }
                req->accessToken = clientData[pos]->accessToken;
            }

            int *code = validate_delegated_action_1(req, cl);
            switch (*code)
            {
                case PERMISSION_DENIED: {
                    printf("PERMISSION_DENIED\n");
                    break;
                }
                case TOKEN_EXPIRED: {
                    printf("TOKEN_EXPIRED\n");
                    break;
                }
                case RESOURCE_NOT_FOUND: {
                    printf("RESOURCE_NOT_FOUND\n");
                    break;
                }
                case PERMISSION_GRANTED: {
                    printf("PERMISSION_GRANTED\n");
                    break;
                }
                case OPERATION_NOT_PERMITTED: {
                    printf("OPERATION_NOT_PERMITTED\n");
                    break;
                }
            }
            if (pos != -1) {
                clientData[pos]->usesLeft--;
            }
        }
    }
    fclose(f);
}

int main(int argc, char *argv[]){

	/* variabila clientului */
	CLIENT *handle;
	
	handle=clnt_create(
		argv[1],		/* numele masinii unde se afla server-ul */
		LOAD_PROG,		/* numele programului disponibil pe server */
		LOAD_VERS,		/* versiunea programului */
		"tcp");			/* tipul conexiunii client-server */
	
	if(handle == NULL) {
		perror("");
		return -1;
	}

	initClient();
	translateClientRequests(argv[2], handle);
	stop_server_1(NULL, handle);
	
	return 0;
}
