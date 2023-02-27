#include <stdio.h> 
#include <rpc/rpc.h>

#include "auth.h"
#include "token.h"

typedef struct UserData {
    char *uid;
    char *requestToken;
    char *accessToken;
    char *refreshToken;
    int *permissions;
    int usesLeft;
} UserData;

UserData **userData;
int usersCount;
int expiry;
int resourcesCount;
char **resources;

FILE *approvalFile = NULL;

void loadUids(char *file) {
    FILE *f = fopen(file, "r");
    if (f == NULL) {
        printf("Error opening %s\n", file);
    }
    char id_buffer[16];

    fscanf(f, "%d", &usersCount);
    userData = malloc(usersCount * sizeof(UserData*));

    for (int i = 0; i < usersCount; i++) {
        fscanf(f, "%s", id_buffer);
        userData[i] = calloc(1, sizeof(UserData));
        userData[i]->uid = strdup(id_buffer);
		userData[i]->permissions = calloc(resourcesCount, sizeof(int));
    }

    fclose(f);
}

// Functions for server initialization
void loadResources(char *file) {
    char buffer[500];

    FILE *f = fopen(file, "r");
    if (f == NULL) {
        printf("Error opening %s\n", file);
    }
    fscanf(f, "%d", &resourcesCount);

    resources = malloc(resourcesCount * sizeof(char *));
    for (int i = 0; i < resourcesCount; i++) {
        fscanf(f, "%s", buffer);
        resources[i] = strdup(buffer);
    }

    fclose(f);
}
void initServer(char **argv) {
    loadUids(argv[1]);
    loadResources(argv[2]);

    approvalFile = fopen(argv[3], "r");
    if (approvalFile == NULL) {
        printf("Error opening %s\n", argv[3]);
    }

    FILE *expiryFile = fopen(argv[4], "r");
    if (approvalFile == NULL) {
        printf("Error opening %s\n", argv[4]);
    }
    fscanf(expiryFile, "%d", &expiry);
    fclose(expiryFile);
}

// Functions to manipulate the server data structures
int getUserIdPos(char *uid) {
    for (int i = 0; i < usersCount; i++) {
        if (!strcmp(userData[i]->uid, uid)) {
            return i;
        }
    }

    return -1;
}
int getUserPosFromReqToken(char *token) {
    for (int i = 0; i < usersCount; i++) {
        char *curToken = userData[i]->requestToken;
        if (curToken != NULL && !strcmp(curToken, token)) {
            return i;
        }
    }

    return -1;
}
int getUserPosFromAuthToken(char *token) {
    for (int i = 0; i < usersCount; i++) {
        char *curToken = userData[i]->accessToken;
        if (curToken != NULL && !strcmp(curToken, token)) {
            return i;
        }
    }

    return -1;
}
int getUserPosFromRefreshToken(char *token) {
    for (int i = 0; i < usersCount; i++) {
        char *curToken = userData[i]->refreshToken;
        if (curToken != NULL && !strcmp(curToken, token)) {
            return i;
        }
    }

    return -1;
}
int getResourcePos(char *uid) {
    for (int i = 0; i < resourcesCount; i++) {
        if (!strcmp(resources[i], uid)) {
            return i;
        }
    }

    return -1;
}

int translatePermission(char *perm) {
    int code = 0;
    if (strchr(perm, 'R') != NULL) code |= READ;

    if (strchr(perm, 'I') != NULL) code |= INSERT;

    if (strchr(perm, 'M') != NULL) code |= MODIFY;

    if (strchr(perm, 'D') != NULL) code |= DELETE;

    if (strchr(perm, 'X') != NULL) code |= EXECUTE;

    return code;
}

// Manipulate current permissions for a given user
void clearPermissions(int userPos) {
    for (int i = 0; i < resourcesCount; i++) {
        userData[userPos]->permissions[i] = 0;
    }
}
void updatePermissions(int userPos, char *res, char *perm) {
    int resPos = getResourcePos(res);
    int code = translatePermission(perm);

    userData[userPos]->permissions[resPos] = code;
}


char ** request_authorization_1_svc(char **uidAddr, struct svc_req *cl) {
    printf("BEGIN %s AUTHZ\n", *uidAddr);
	char *uid = *uidAddr;
    int userPos = getUserIdPos(uid);
    if (userPos == -1) {
		char **res = malloc(sizeof(char**));
		*res = strdup("\0");

        return res;
    }
    char *requestToken = generate_access_token(uid);
    printf("  RequestToken = %s\n", requestToken);
    userData[userPos]->requestToken = requestToken;
    // Clear old permissions
    clearPermissions(userPos);
	
	char **res = malloc(sizeof(char**));
	*res = requestToken;

    return res;
}

// Functions to perform signing and validation of signature
char *signToken(char *token) {
    token[0]++;

    return token;
}
char *unsignToken(char *token) {
    token[0]--;

    return token;
}

// Handle transalation of user approval
void parseApprovalLine(char *line, int userPos) {
    char *res, *perm;

    res = strtok(line, ",\n");
    perm = strtok(NULL, ",\n");

    while (res != NULL) {
        updatePermissions(userPos, res, perm);
        res = strtok(NULL, ",\n");
        perm = strtok(NULL, ",\n");
    }
}
int getEndUserApproval(int userPos) {
    int bufferLen = 500;
    char buffer[500];

    fgets(buffer, bufferLen, approvalFile);

    if (!strncmp(buffer, "*,-", 3)) {
        return 0;
    }

    parseApprovalLine(buffer, userPos);

    return 1;   
}


char ** approve_request_token_1_svc(char **requestTokenAddr, struct svc_req *cl) {
	char *requestToken = *requestTokenAddr;
    int userPos = getUserPosFromReqToken(requestToken);
	char **res = malloc(sizeof(char*));
    // Get approval and add new permissions on the server
    if(!getEndUserApproval(userPos)) {
        *res = strdup(requestToken);
    } else {
		*res = signToken(strdup(requestToken));
	}

    return res;
}

Auth_Response *request_access_token_1_svc(Auth_Request *req, struct svc_req *cl) {
	char *requestToken = req->requestToken;
    int refresh = req->shouldRefresh;
    Auth_Response *res = calloc(1, sizeof(Auth_Response));
    // Unsign the received token to compare with the existing request token
    unsignToken(requestToken);
    int userPos = getUserPosFromReqToken(requestToken);

    if(userPos == -1) {
        res->status = REQUEST_DENIED;
        res->accessToken = strdup("\0");
        res->refreshToken = strdup("\0");

        return res;
    }

    if (userData[userPos]->accessToken != NULL) {
        free(userData[userPos]->accessToken);
    }
    userData[userPos]->accessToken = generate_access_token(requestToken);
    res->accessToken = userData[userPos]->accessToken;
    printf("  AccessToken = %s\n", res->accessToken);

    if (userData[userPos]->refreshToken != NULL) {
        free(userData[userPos]->refreshToken);
    }
    userData[userPos]->refreshToken = NULL;
    if (refresh) {
        userData[userPos]->refreshToken = generate_access_token(res->accessToken);
        printf("  RefreshToken = %s\n", userData[userPos]->refreshToken);
    }
    res->refreshToken = userData[userPos]->refreshToken == NULL ? strdup("\0") : userData[userPos]->refreshToken;

    userData[userPos]->usesLeft = expiry;

    res->status = PERMISSION_GRANTED;
    res->expiry = expiry;
    
    return res;
}

Auth_Response * refresh_access_token_1_svc(char **tokenAddr, struct svc_req *cl) {
	char *refreshToken = *tokenAddr;
    Auth_Response *res = calloc(1, sizeof(Auth_Response));
    int userPos = getUserPosFromRefreshToken(refreshToken);

    printf("BEGIN %s AUTHZ REFRESH\n", userData[userPos]->uid);

    if (userData[userPos]->accessToken != NULL) {
        free(userData[userPos]->accessToken);
    }
    userData[userPos]->accessToken = generate_access_token(refreshToken);
    res->accessToken = userData[userPos]->accessToken;

    if (userData[userPos]->refreshToken != NULL) {
        free(userData[userPos]->refreshToken);
    }
    userData[userPos]->refreshToken = generate_access_token(res->accessToken);
    res->refreshToken = userData[userPos]->refreshToken;

    printf("  AccessToken = %s\n", res->accessToken);
    printf("  RefreshToken = %s\n", res->refreshToken);
 
    userData[userPos]->usesLeft = expiry;

    res->status = PERMISSION_GRANTED;
    res->expiry = expiry;
    
    return res;  
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

int * validate_delegated_action_1_svc(Action_Request *req, struct svc_req *cl) {
	char* accessToken = req->accessToken;
	char *resource = req->resource;
	char *action = req->action;
    int userPos = getUserPosFromAuthToken(accessToken);
    int resPos = getResourcePos(resource);
	int *res = malloc(sizeof(int));

    if (userPos == -1) {
        *res = PERMISSION_DENIED;

        printf("DENY (%s,%s,%s,%d)\n",
            action,
            resource,
            accessToken,
            0
        );

		return res;
    }

    if (userData[userPos]->usesLeft <= 0) {
        *res = TOKEN_EXPIRED;
        userData[userPos]->accessToken = strdup("\0");

        printf("DENY (%s,%s,%s,%d)\n",
            action,
            resource,
            userData[userPos]->accessToken,
            userData[userPos]->usesLeft
        );

		return res;
    } else {
        userData[userPos]->usesLeft--;
    }


    if (resPos == -1) {
        *res = RESOURCE_NOT_FOUND;

        printf("DENY (%s,%s,%s,%d)\n",
            action,
            resource,
            userData[userPos]->accessToken,
            userData[userPos]->usesLeft
        );
        
		return res;
    }

    int perm = userData[userPos]->permissions[resPos];
    int actionCode = translateAction(action);
    if (actionCode != -1 && perm & actionCode) {
        *res = PERMISSION_GRANTED;
        printf("PERMIT (%s,%s,%s,%d)\n",
            action,
            resource,
            accessToken,
            userData[userPos]->usesLeft
        );

		return res;
    } else {
        *res = OPERATION_NOT_PERMITTED;
        printf("DENY (%s,%s,%s,%d)\n",
            action,
            resource,
            accessToken,
            userData[userPos]->usesLeft
        );

		return res;
    }
}

 void *stop_server_1_svc(void *p, struct svc_req *cl) {
    exit(0);
 }
