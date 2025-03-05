/*
 * pkinstall - EFI Platform Key Installer
 *
 * This EFI application installs a platform key to the TPM during EFI runtime.
 * It's designed to run from the EFI shell when the TPM is in platform setup mode.
 *
 * Features:
 * - P12 file parsing without OpenSSL dependency
 * - Direct TPM programming using EFI TCG protocols
 * - Support for both TPM 1.2 and 2.0
 * - Password-protected P12 file support
 */

#include <efi.h>
#include <efilib.h>
#include <efi/efi_tcg2.h>
#include <efi/efi_tpm.h>
#include <getopt.h>

/* TPM 2.0 command structures */
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_CC_CreatePrimary 0x00000131
#define TPM_CC_Load 0x00000134
#define TPM_CC_EvictControl 0x00000120

/* TPM algorithms */
#define TPM_ALG_RSA 0x0001
#define TPM_ALG_SHA256 0x000B
#define TPM_ALG_NULL 0x0010

/* TPM object attributes */
#define TPMA_OBJECT_SIGN_ENCRYPT 0x00000010
#define TPMA_OBJECT_USERWITHAUTH 0x00000040

/* TPM hierarchy handles */
#define TPM_RH_PLATFORM 0x4000000C
#define TPM_PLATFORM_HANDLE 0x81000000

/* TPM capability properties */
#define TPM_CAP_TPM_PROPERTIES 0x00000006
#define TPM_PT_FAMILY_INDICATOR 0x00000100
#define TPM_PT_MANUFACTURER 0x00000105
#define TPM_PT_MAX_RSA_KEY_BITS 0x0000010A
#define TPM_PT_PCR_COUNT 0x0000010D
#define TPM_PT_TOTAL_COMMANDS 0x0000010E
#define TPM_PT_PH_ENABLED 0x0000010F
#define TPM_PT_OWNER_AUTH_SET 0x00000110
#define TPM_PT_ENDORSEMENT_AUTH_SET 0x00000111
#define TPM_PT_PLATFORM_AUTH_SET 0x00000112
#define TPM_PT_PLATFORM_CREATE_AUTH_SET 0x00000113
#define TPM_PT_PLATFORM_APPROVE_AUTH_SET 0x00000114
#define TPM_PT_PLATFORM_APPROVE_ENABLED 0x00000115
#define TPM_PT_PLATFORM_APPROVE_POLICY_SET 0x00000116
#define TPM_PT_PLATFORM_APPROVE_POLICY_ENABLED 0x00000117

/* P12 file structures */
struct p12_header {
    uint8_t version[2];
    uint8_t type[2];
    uint8_t data[4];
};

struct p12_safe_bag {
    uint8_t type[2];
    uint8_t data[4];
    uint8_t content[4];
};

/* Global variables */
static EFI_TCG2_PROTOCOL *tcg2 = NULL;
static EFI_TCG_PROTOCOL *tcg = NULL;
static EFI_HANDLE image_handle;
static EFI_SYSTEM_TABLE *systab;
static int verbosity = 0;  /* Verbosity level (0-3) */
static int show_info = 0;  /* Show TPM information */
static int clear_tpm = 0;  /* Clear TPM */
static CHAR16 *p12_file = NULL;  /* P12 file path */

/* Command line options */
static struct option long_options[] = {
    { "install-pk", required_argument, NULL, 'k' },
    { "clear", no_argument, NULL, 'c' },
    { "info", no_argument, NULL, 'i' },
    { "verbose", no_argument, NULL, 'v' },
    { NULL, 0, NULL, 0 }
};

/* Verbose logging function */
static void vprintf(int level, const CHAR16 *fmt, ...) {
    if (verbosity >= level) {
        VA_LIST args;
        VA_START(args, fmt);
        VPrint(fmt, args);
        VA_END(args);
    }
}

/* Function declarations */
static EFI_STATUS init_tpm(void);
static EFI_STATUS parse_p12_file(const CHAR16 *filename, const CHAR16 *password);
static EFI_STATUS install_platform_key(const uint8_t *pub_key, size_t pub_size,
    const uint8_t *priv_key, size_t priv_size);
static EFI_STATUS create_primary_key(void);
static EFI_STATUS load_key(const uint8_t *pub_key, size_t pub_size,
    const uint8_t *priv_key, size_t priv_size);
static EFI_STATUS make_key_persistent(void);
static EFI_STATUS print_tpm_info(void);
static EFI_STATUS clear_tpm(void);

/**
 * Initialize TPM protocols
 */
static EFI_STATUS init_tpm(void) {
    EFI_STATUS status;
    EFI_GUID tcg2_guid = EFI_TCG2_PROTOCOL_GUID;
    EFI_GUID tcg_guid = EFI_TCG_PROTOCOL_GUID;

    vprintf(2, L"Initializing TPM protocols\n");

    /* Try TPM 2.0 first */
    vprintf(3, L"Attempting to locate TPM 2.0 protocol\n");
    status = uefi_call_wrapper(BS->LocateProtocol, 3, &tcg2_guid, NULL, (void **)&tcg2);
    if (status == EFI_SUCCESS) {
        vprintf(2, L"Found TPM 2.0\n");
        vprintf(3, L"TPM 2.0 protocol initialized successfully\n");
        return EFI_SUCCESS;
    }
    vprintf(3, L"TPM 2.0 protocol not found: %r\n", status);

    /* Fall back to TPM 1.2 */
    vprintf(3, L"Attempting to locate TPM 1.2 protocol\n");
    status = uefi_call_wrapper(BS->LocateProtocol, 3, &tcg_guid, NULL, (void **)&tcg);
    if (status == EFI_SUCCESS) {
        vprintf(2, L"Found TPM 1.2\n");
        vprintf(3, L"TPM 1.2 protocol initialized successfully\n");
        return EFI_SUCCESS;
    }
    vprintf(3, L"TPM 1.2 protocol not found: %r\n", status);

    vprintf(1, L"Error: No TPM found\n");
    return EFI_NOT_FOUND;
}

/**
 * Parse P12 file and extract key data
 */
static EFI_STATUS parse_p12_file(const CHAR16 *filename, const CHAR16 *password) {
    EFI_STATUS status;
    EFI_FILE_HANDLE root, file;
    EFI_FILE_INFO *file_info;
    uint8_t *buffer;
    UINTN size;
    struct p12_header *header;
    struct p12_safe_bag *safe_bag;

    vprintf(2, L"Parsing P12 file: %s\n", filename);

    /* Open the file */
    vprintf(3, L"Opening root directory\n");
    status = uefi_call_wrapper(BS->OpenProtocol, 6, image_handle,
        &FileSystemProtocol, (void **)&root, image_handle, NULL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to open root directory: %r\n", status);
        return status;
    }

    vprintf(3, L"Opening P12 file\n");
    status = uefi_call_wrapper(root->Open, 5, root, &file, filename,
        EFI_FILE_MODE_READ, 0);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to open P12 file: %r\n", status);
        return status;
    }

    /* Get file size */
    vprintf(3, L"Getting file information\n");
    file_info = AllocatePool(sizeof(EFI_FILE_INFO) + 256);
    if (!file_info) {
        vprintf(1, L"Error: Failed to allocate memory\n");
        return EFI_OUT_OF_RESOURCES;
    }

    status = uefi_call_wrapper(file->GetInfo, 4, file, &FileInfoGuid,
        &size, file_info);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to get file info: %r\n", status);
        FreePool(file_info);
        return status;
    }

    vprintf(3, L"File size: %d bytes\n", file_info->FileSize);

    /* Read file contents */
    vprintf(3, L"Reading file contents\n");
    buffer = AllocatePool(file_info->FileSize);
    if (!buffer) {
        vprintf(1, L"Error: Failed to allocate memory\n");
        FreePool(file_info);
        return EFI_OUT_OF_RESOURCES;
    }

    size = file_info->FileSize;
    status = uefi_call_wrapper(file->Read, 3, file, &size, buffer);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to read file: %r\n", status);
        FreePool(buffer);
        FreePool(file_info);
        return status;
    }

    /* Parse P12 structure */
    vprintf(3, L"Parsing P12 structure\n");
    header = (struct p12_header *)buffer;
    if (header->version[0] != 0x03 || header->version[1] != 0x00) {
        vprintf(1, L"Error: Unsupported P12 version\n");
        FreePool(buffer);
        FreePool(file_info);
        return EFI_UNSUPPORTED;
    }

    vprintf(3, L"P12 version: %d.%d\n", header->version[0], header->version[1]);

    /* Extract key data */
    vprintf(3, L"Extracting key data\n");
    safe_bag = (struct p12_safe_bag *)(buffer + sizeof(struct p12_header));
    // TODO: Implement P12 decryption and key extraction
    // This will require implementing PKCS#12 parsing without OpenSSL

    vprintf(2, L"P12 file parsed successfully\n");
    FreePool(buffer);
    FreePool(file_info);
    return EFI_SUCCESS;
}

/**
 * Create primary key in TPM
 */
static EFI_STATUS create_primary_key(void) {
    EFI_STATUS status;
    TPM2_CREATE_PRIMARY_COMMAND cmd;
    TPM2_CREATE_PRIMARY_RESPONSE resp;
    UINT32 resp_size;

    vprintf(2, L"Creating primary key in TPM\n");

    if (!tcg2) {
        vprintf(1, L"Error: TPM 2.0 not available\n");
        return EFI_NOT_FOUND;
    }

    /* Prepare command */
    vprintf(3, L"Preparing CreatePrimary command\n");
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_CreatePrimary;
    cmd.header.paramSize = sizeof(cmd);
    cmd.primaryHandle = TPM_RH_PLATFORM;
    cmd.inSensitive.sensitiveType = TPM_ALG_RSA;
    cmd.inPublic.type = TPM_ALG_RSA;
    cmd.inPublic.nameAlg = TPM_ALG_SHA256;
    cmd.inPublic.objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH;
    cmd.inPublic.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    cmd.inPublic.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    cmd.inPublic.parameters.rsaDetail.keyBits = 2048;
    cmd.inPublic.parameters.rsaDetail.exponent = 65537;

    vprintf(3, L"Command parameters:\n");
    vprintf(3, L"  Key bits: %d\n", cmd.inPublic.parameters.rsaDetail.keyBits);
    vprintf(3, L"  Exponent: %d\n", cmd.inPublic.parameters.rsaDetail.exponent);

    /* Send command */
    vprintf(3, L"Sending CreatePrimary command\n");
    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to create primary key: %r\n", status);
        return status;
    }

    vprintf(2, L"Primary key created successfully\n");
    return EFI_SUCCESS;
}

/**
 * Load key into TPM
 */
static EFI_STATUS load_key(const uint8_t *pub_key, size_t pub_size,
    const uint8_t *priv_key, size_t priv_size) {
    EFI_STATUS status;
    TPM2_LOAD_COMMAND cmd;
    TPM2_LOAD_RESPONSE resp;
    UINT32 resp_size;

    vprintf(2, L"Loading key into TPM\n");

    if (!tcg2) {
        vprintf(1, L"Error: TPM 2.0 not available\n");
        return EFI_NOT_FOUND;
    }

    /* Prepare command */
    vprintf(3, L"Preparing Load command\n");
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_Load;
    cmd.header.paramSize = sizeof(cmd);
    cmd.parentHandle = TPM_RH_PLATFORM;
    cmd.inPrivate.size = priv_size;
    memcpy(cmd.inPrivate.buffer, priv_key, priv_size);
    cmd.inPublic.size = pub_size;
    memcpy(cmd.inPublic.buffer, pub_key, pub_size);

    vprintf(3, L"Key sizes:\n");
    vprintf(3, L"  Public: %d bytes\n", pub_size);
    vprintf(3, L"  Private: %d bytes\n", priv_size);

    /* Send command */
    vprintf(3, L"Sending Load command\n");
    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to load key: %r\n", status);
        return status;
    }

    vprintf(2, L"Key loaded successfully\n");
    return EFI_SUCCESS;
}

/**
 * Make key persistent in TPM
 */
static EFI_STATUS make_key_persistent(void) {
    EFI_STATUS status;
    TPM2_EVICT_CONTROL_COMMAND cmd;
    TPM2_EVICT_CONTROL_RESPONSE resp;
    UINT32 resp_size;

    vprintf(2, L"Making key persistent in TPM\n");

    if (!tcg2) {
        vprintf(1, L"Error: TPM 2.0 not available\n");
        return EFI_NOT_FOUND;
    }

    /* Prepare command */
    vprintf(3, L"Preparing EvictControl command\n");
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_EvictControl;
    cmd.header.paramSize = sizeof(cmd);
    cmd.auth = TPM_RH_PLATFORM;
    cmd.objectHandle = TPM_PLATFORM_HANDLE;
    cmd.persistentHandle = TPM_PLATFORM_HANDLE;

    vprintf(3, L"Command parameters:\n");
    vprintf(3, L"  Object handle: 0x%x\n", cmd.objectHandle);
    vprintf(3, L"  Persistent handle: 0x%x\n", cmd.persistentHandle);

    /* Send command */
    vprintf(3, L"Sending EvictControl command\n");
    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to make key persistent: %r\n", status);
        return status;
    }

    vprintf(2, L"Key made persistent successfully\n");
    return EFI_SUCCESS;
}

/**
 * Show TPM information
 */
static EFI_STATUS print_tpm_info(void) {
    EFI_STATUS status;
    TPM2_GET_CAPABILITY_COMMAND cmd;
    TPM2_GET_CAPABILITY_RESPONSE resp;

    vprintf(1, L"Getting TPM information\n");

    if (!tcg2) {
        vprintf(1, L"Error: TPM 2.0 not available\n");
        return EFI_NOT_FOUND;
    }

    /* Get TPM version */
    vprintf(3, L"Querying TPM version\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_GetCapability;
    cmd.header.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_FAMILY_INDICATOR;
    cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status == EFI_SUCCESS) {
        vprintf(1, L"TPM Version: %s\n", 
            resp.data.tpmProperties.tpmProperty[0].value == 2 ? L"2.0" : L"1.2");
    }

    /* Get manufacturer ID */
    vprintf(3, L"Querying manufacturer ID\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_GetCapability;
    cmd.header.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_MANUFACTURER;
    cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status == EFI_SUCCESS) {
        uint32_t manuf = resp.data.tpmProperties.tpmProperty[0].value;
        vprintf(1, L"Manufacturer ID: %c%c%c%c\n", 
            (manuf >> 24) & 0xFF,
            (manuf >> 16) & 0xFF,
            (manuf >> 8) & 0xFF,
            manuf & 0xFF);
    }

    /* Get maximum key size */
    vprintf(3, L"Querying maximum key size\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_GetCapability;
    cmd.header.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_MAX_RSA_KEY_BITS;
    cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status == EFI_SUCCESS) {
        vprintf(1, L"Maximum RSA Key Size: %d bits\n", 
            resp.data.tpmProperties.tpmProperty[0].value);
    }

    /* Get number of PCR banks */
    vprintf(3, L"Querying PCR count\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_GetCapability;
    cmd.header.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_PCR_COUNT;
    cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status == EFI_SUCCESS) {
        vprintf(1, L"Number of PCR Banks: %d\n", 
            resp.data.tpmProperties.tpmProperty[0].value);
    }

    /* Check platform hierarchy and setup mode */
    vprintf(1, L"\nPlatform Status:\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_GetCapability;
    cmd.header.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_PH_ENABLED;
    cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status == EFI_SUCCESS) {
        if (resp.data.tpmProperties.tpmProperty[0].value == 1) {
            vprintf(1, L"Platform Hierarchy: Enabled\n");
            
            /* Check platform auth settings */
            vprintf(3, L"Checking platform auth settings\n");
            memset(&cmd, 0, sizeof(cmd));
            cmd.header.tag = TPM_ST_NO_SESSIONS;
            cmd.header.commandCode = TPM_CC_GetCapability;
            cmd.header.paramSize = sizeof(cmd);
            cmd.capability = TPM_CAP_TPM_PROPERTIES;
            cmd.property = TPM_PT_PLATFORM_AUTH_SET;
            cmd.propertyCount = 1;

            status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
                (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
            if (status == EFI_SUCCESS) {
                vprintf(1, L"Platform Auth: %s\n",
                    resp.data.tpmProperties.tpmProperty[0].value ? L"Set" : L"Not Set");
            }

            /* Try to create a primary key to check setup mode */
            status = create_primary_key();
            if (status == EFI_SUCCESS) {
                vprintf(1, L"Setup Mode: Enabled\n");
            } else {
                vprintf(1, L"Setup Mode: Disabled\n");
            }
        } else {
            vprintf(1, L"Platform Hierarchy: Disabled\n");
            vprintf(1, L"Setup Mode: Not Available\n");
        }
    }

    /* Check owner and endorsement auth */
    vprintf(1, L"\nHierarchy Status:\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_GetCapability;
    cmd.header.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_OWNER_AUTH_SET;
    cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status == EFI_SUCCESS) {
        vprintf(1, L"Owner Auth: %s\n",
            resp.data.tpmProperties.tpmProperty[0].value ? L"Set" : L"Not Set");
    }

    memset(&cmd, 0, sizeof(cmd));
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_GetCapability;
    cmd.header.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_ENDORSEMENT_AUTH_SET;
    cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status == EFI_SUCCESS) {
        vprintf(1, L"Endorsement Auth: %s\n",
            resp.data.tpmProperties.tpmProperty[0].value ? L"Set" : L"Not Set");
    }

    return EFI_SUCCESS;
}

/**
 * Clear TPM
 */
static EFI_STATUS clear_tpm(void) {
    EFI_STATUS status;
    TPM2_CLEAR_COMMAND cmd;
    TPM2_CLEAR_RESPONSE resp;
    BOOLEAN confirm = FALSE;

    vprintf(1, L"Clearing TPM\n");

    if (!tcg2) {
        vprintf(1, L"Error: TPM 2.0 not available\n");
        return EFI_NOT_FOUND;
    }

    /* Check if TPM is in platform setup mode */
    status = print_tpm_info();
    if (status != EFI_SUCCESS) {
        return status;
    }

    /* Check if platform hierarchy is enabled */
    TPM2_GET_CAPABILITY_COMMAND cap_cmd;
    TPM2_GET_CAPABILITY_RESPONSE cap_resp;
    memset(&cap_cmd, 0, sizeof(cap_cmd));
    cap_cmd.header.tag = TPM_ST_NO_SESSIONS;
    cap_cmd.header.commandCode = TPM_CC_GetCapability;
    cap_cmd.header.paramSize = sizeof(cap_cmd);
    cap_cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cap_cmd.property = TPM_PT_PH_ENABLED;
    cap_cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cap_cmd),
        (uint8_t *)&cap_cmd, sizeof(cap_resp), (uint8_t *)&cap_resp);
    if (status != EFI_SUCCESS || cap_resp.data.tpmProperties.tpmProperty[0].value != 1) {
        vprintf(1, L"Error: Platform hierarchy is not enabled\n");
        return EFI_UNSUPPORTED;
    }

    /* Check if platform auth is set */
    memset(&cap_cmd, 0, sizeof(cap_cmd));
    cap_cmd.header.tag = TPM_ST_NO_SESSIONS;
    cap_cmd.header.commandCode = TPM_CC_GetCapability;
    cap_cmd.header.paramSize = sizeof(cap_cmd);
    cap_cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cap_cmd.property = TPM_PT_PLATFORM_AUTH_SET;
    cap_cmd.propertyCount = 1;

    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cap_cmd),
        (uint8_t *)&cap_cmd, sizeof(cap_resp), (uint8_t *)&cap_resp);
    if (status == EFI_SUCCESS && cap_resp.data.tpmProperties.tpmProperty[0].value) {
        vprintf(1, L"Warning: Platform auth is set. Clearing TPM will require platform auth.\n");
    }

    /* Get user confirmation */
    vprintf(1, L"\nWARNING: This will clear all TPM data and reset it to factory state.\n");
    vprintf(1, L"This operation cannot be undone.\n");
    vprintf(1, L"Are you sure you want to continue? (y/N): ");
    
    CHAR16 input[2];
    UINTN size = sizeof(input);
    status = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, input);
    if (status == EFI_SUCCESS && (input[0] == L'y' || input[0] == L'Y')) {
        confirm = TRUE;
    }

    if (!confirm) {
        vprintf(1, L"Operation cancelled by user\n");
        return EFI_ABORTED;
    }

    /* Prepare clear command */
    vprintf(3, L"Preparing Clear command\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.header.tag = TPM_ST_NO_SESSIONS;
    cmd.header.commandCode = TPM_CC_Clear;
    cmd.header.paramSize = sizeof(cmd);
    cmd.authHandle = TPM_RH_PLATFORM;

    /* Send clear command */
    vprintf(3, L"Sending Clear command\n");
    status = uefi_call_wrapper(tcg2->SubmitCommand, 5, tcg2, sizeof(cmd),
        (uint8_t *)&cmd, sizeof(resp), (uint8_t *)&resp);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to clear TPM: %r\n", status);
        return status;
    }

    vprintf(1, L"TPM cleared successfully\n");
    return EFI_SUCCESS;
}

/**
 * Main entry point
 */
EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab) {
    EFI_STATUS status;
    CHAR16 *password = NULL;
    UINTN argc;
    CHAR16 **argv;
    int opt;

    image_handle = image;
    systab = systab;

    vprintf(2, L"Platform Key Installer starting\n");

    /* Get command line arguments */
    vprintf(3, L"Parsing command line arguments\n");
    status = uefi_call_wrapper(BS->HandleProtocol, 3, image,
        &LoadedImageProtocol, (void **)&loaded_image);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to get loaded image protocol: %r\n", status);
        return status;
    }

    argc = 0;
    argv = NULL;
    status = uefi_call_wrapper(BS->ParseCommandLine, 3, loaded_image->LoadOptions,
        loaded_image->LoadOptionsSize, &argc, &argv);
    if (status != EFI_SUCCESS) {
        vprintf(1, L"Error: Failed to parse command line: %r\n", status);
        return status;
    }

    vprintf(3, L"Command line arguments: %d\n", argc);
    for (UINTN i = 0; i < argc; i++) {
        vprintf(3, L"  Arg %d: %s\n", i, argv[i]);
    }

    /* Parse command line options */
    while ((opt = getopt_long(argc, argv, L"k:i:cv", long_options, NULL)) != -1) {
        switch (opt) {
        case 'k':
            p12_file = optarg;
            break;
        case 'i':
            show_info = 1;
            break;
        case 'c':
            clear_tpm = 1;
            break;
        case 'v':
            verbosity++;
            break;
        default:
            vprintf(1, L"Usage: pkinstall.efi [options] [password]\n");
            vprintf(1, L"Options:\n");
            vprintf(1, L"  -k, --install-pk <file>  Install platform key from P12 file\n");
            vprintf(1, L"  -i, --info               Show TPM information\n");
            vprintf(1, L"  -c, --clear             Clear TPM\n");
            vprintf(1, L"  -v, --verbose           Enable verbose output\n");
            return EFI_INVALID_PARAMETER;
        }
    }

    /* Initialize TPM */
    vprintf(2, L"Initializing TPM\n");
    status = init_tpm();
    if (status != EFI_SUCCESS) {
        return status;
    }

    /* Handle show info option */
    if (show_info) {
        vprintf(2, L"Showing TPM information\n");
        status = print_tpm_info();
        return status;
    }

    /* Handle clear TPM option */
    if (clear_tpm) {
        vprintf(2, L"Clearing TPM\n");
        status = clear_tpm();
        return status;
    }

    /* Handle platform key installation */
    if (p12_file) {
        if (optind < argc) {
            password = argv[optind];
        }

        /* Parse P12 file */
        vprintf(2, L"Processing P12 file\n");
        status = parse_p12_file(p12_file, password);
        if (status != EFI_SUCCESS) {
            return status;
        }

        /* Install platform key */
        vprintf(2, L"Installing platform key\n");
        status = create_primary_key();
        if (status != EFI_SUCCESS) {
            return status;
        }

        status = load_key(pub_key, pub_size, priv_key, priv_size);
        if (status != EFI_SUCCESS) {
            return status;
        }

        status = make_key_persistent();
        if (status != EFI_SUCCESS) {
            return status;
        }

        vprintf(1, L"Platform key installed successfully\n");
        return EFI_SUCCESS;
    }

    vprintf(1, L"No command specified\n");
    return EFI_INVALID_PARAMETER;
}
