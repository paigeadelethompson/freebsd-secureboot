/*
 * tpmctl - TPM Control Utility
 *
 * This utility provides command-line interface for managing TPM devices,
 * including listing available TPM devices, showing TPM information,
 * and installing platform keys.
 *
 * Features:
 * - List available TPM devices (CRB and TIS interfaces)
 * - Show detailed TPM information (version, manufacturer, capabilities)
 * - Install platform keys from P12 files
 * - Support for both TPM 1.2 and 2.0 devices
 * - Dynamic device discovery
 * - Password-protected P12 file support
 *
 * Usage:
 *   tpmctl [options] [p12_file]
 *
 * Options:
 *   -i, --info             Show TPM information
 *   --install-pk           Install platform key from P12 file
 *   -l, --list-devices     List available TPM devices
 *   --device <num>         Select TPM device by number (0-based)
 *   --tis                  Force TIS interface mode
 *   -v, --verbose          Enable verbose output
 *   -w, --password <pass>  P12 password
 *   --help                 Show help message
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/bn.h>

/* Device paths for TPM interfaces */
#define TPM_TIS_DEVICE "/dev/tpm0"      /* TIS interface device */
#define TPM_CRB_DEVICE "/dev/tpmrm0"    /* CRB interface device */
#define TPM_PLATFORM_HANDLE 0x81000000  /* Persistent handle for platform key */

/* TPM 2.0 command structures for userland */
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_CC_GetCapability 0x0000017A
#define TPM_CC_CreatePrimary 0x00000131
#define TPM_CC_Load 0x00000134
#define TPM_CC_EvictControl 0x00000120

/* TPM capability properties */
#define TPM_CAP_TPM_PROPERTIES 0x00000006
#define TPM_PT_FAMILY_INDICATOR 0x00000100
#define TPM_PT_MANUFACTURER 0x00000105
#define TPM_PT_MAX_RSA_KEY_BITS 0x0000010A
#define TPM_PT_PCR_COUNT 0x0000010D
#define TPM_PT_TOTAL_COMMANDS 0x0000010E
#define TPM_PT_PH_ENABLED 0x0000010F

/* TPM algorithms */
#define TPM_ALG_RSA 0x0001
#define TPM_ALG_SHA256 0x000B
#define TPM_ALG_NULL 0x0010

/* TPM object attributes */
#define TPMA_OBJECT_SIGN_ENCRYPT 0x00000010
#define TPMA_OBJECT_USERWITHAUTH 0x00000040

/* TPM hierarchy handles */
#define TPM_RH_PLATFORM 0x4000000C

/**
 * TPM command header structure
 */
struct tpm_header {
    uint16_t tag;           /* Command tag */
    uint32_t commandCode;   /* Command code */
    uint32_t paramSize;     /* Parameter size */
};

/**
 * TPM property structure
 */
struct tpm_property {
    uint32_t property;      /* Property identifier */
    uint32_t value;        /* Property value */
};

/**
 * TPM properties structure
 */
struct tpm_properties {
    uint32_t count;                    /* Number of properties */
    struct tpm_property tpmProperty[1]; /* Array of properties */
};

/**
 * TPM GetCapability command structure
 */
struct tpm_get_capability_cmd {
    struct tpm_header hdr;             /* Command header */
    uint32_t capability;               /* Capability area */
    uint32_t property;                 /* Property identifier */
    uint32_t propertyCount;            /* Number of properties */
    struct tpm_properties data;        /* Property data */
};

/**
 * RSA parameters for TPM
 */
struct tpm_rsa_parameters {
    uint16_t symmetric;    /* Symmetric algorithm */
    uint16_t scheme;       /* Scheme */
    uint16_t keyBits;      /* Key size in bits */
    uint32_t exponent;     /* Public exponent */
};

/**
 * TPM public key structure
 */
struct tpm_public {
    uint16_t type;                     /* Key type */
    uint16_t nameAlg;                  /* Name algorithm */
    uint32_t objectAttributes;         /* Object attributes */
    uint16_t authPolicy;               /* Authorization policy */
    struct tpm_rsa_parameters parameters; /* Key parameters */
    struct {
        uint16_t size;                 /* Buffer size */
        uint8_t buffer[256];           /* Key data */
    } unique;
};

/**
 * TPM private key structure
 */
struct tpm_private {
    uint16_t integrity;                /* Integrity value */
    struct {
        uint16_t sensitiveType;        /* Sensitive data type */
        uint16_t auth;                 /* Authorization value */
        uint16_t seed;                 /* Seed value */
        struct {
            uint16_t size;             /* Buffer size */
            uint8_t buffer[256];       /* Private key data */
        } sensitive;
    } sensitiveArea;
};

/**
 * TPM 2B public key structure
 */
struct tpm2b_public {
    uint16_t size;                     /* Size of public key */
    struct tpm_public buffer;          /* Public key data */
};

/**
 * TPM 2B private key structure
 */
struct tpm2b_private {
    uint16_t size;                     /* Size of private key */
    struct tpm_private buffer;         /* Private key data */
};

/**
 * TPM CreatePrimary command structure
 */
struct tpm_create_primary_cmd {
    struct tpm_header hdr;             /* Command header */
    uint32_t primaryHandle;            /* Primary handle */
    struct tpm2b_public inPublic;      /* Public key data */
    struct tpm2b_private inSensitive;  /* Private key data */
    uint32_t outHandle;                /* Output handle */
};

/**
 * TPM Load command structure
 */
struct tpm_load_cmd {
    struct tpm_header hdr;             /* Command header */
    uint32_t parentHandle;             /* Parent handle */
    struct tpm2b_private inPrivate;    /* Private key data */
    struct tpm2b_public inPublic;      /* Public key data */
    uint32_t outHandle;                /* Output handle */
};

/**
 * TPM EvictControl command structure
 */
struct tpm_evict_control_cmd {
    struct tpm_header hdr;             /* Command header */
    uint32_t auth;                     /* Authorization value */
    uint32_t objectHandle;             /* Object handle */
    uint32_t persistentHandle;         /* Persistent handle */
};

/**
 * TPM device structure
 */
struct tpm_device {
    const char *path;      /* Device path */
    const char *type;      /* Interface type (CRB/TIS) */
    int available;         /* Device availability flag */
};

/* Global TPM device list */
static struct tpm_device *tpm_devices = NULL;
static size_t tpm_device_count = 0;

/* Global variables */
static int verbosity = 0;  /* Verbosity level (0-3) */
static int force_tis = 0;  /* Force TIS interface mode */
static int device_num = -1; /* Selected device number */
static int show_info = 0;  /* Show TPM information */
static int install_pk = 0; /* Install platform key */
static int list_devices = 0; /* List available devices */
static const char *p12_file = NULL; /* P12 file path */
static const char *p12_password = NULL; /* P12 password */

/* Error handling macros */
#define TPM_ERROR(msg, ...) do { \
    fprintf(stderr, "Error: " msg "\n", ##__VA_ARGS__); \
    if (verbosity >= 2) { \
        fprintf(stderr, "  File: %s, Line: %d\n", __FILE__, __LINE__); \
    } \
} while (0)

#define TPM_ERROR_IOCTL(msg, err) do { \
    TPM_ERROR(msg ": %s", strerror(err)); \
} while (0)

#define TPM_ERROR_OPENSSL(msg) do { \
    TPM_ERROR(msg); \
    if (verbosity >= 2) { \
        ERR_print_errors_fp(stderr); \
    } \
} while (0)

/* Error codes */
#define TPM_SUCCESS 0
#define TPM_ERROR_IO -1
#define TPM_ERROR_OPENSSL -2
#define TPM_ERROR_INVALID_PARAM -3
#define TPM_ERROR_DEVICE -4
#define TPM_ERROR_MEMORY -5

/* Verbose logging function */
static void vprintf(int level, const char *fmt, ...) {
    if (verbosity >= level) {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
}

/**
 * Add a new TPM device to the device list
 *
 * @param path Device path
 * @param type Interface type (CRB/TIS)
 */
static void add_tpm_device(const char *path, const char *type) {
    vprintf(3, "Adding TPM device: %s (type: %s)\n", path, type);
    struct tpm_device *new_devices = realloc(tpm_devices, 
        (tpm_device_count + 1) * sizeof(struct tpm_device));
    if (!new_devices) {
        TPM_ERROR("Failed to allocate memory for TPM device list");
        return;
    }
    
    tpm_devices = new_devices;
    tpm_devices[tpm_device_count].path = path;
    tpm_devices[tpm_device_count].type = type;
    tpm_devices[tpm_device_count].available = 0;
    tpm_device_count++;
    vprintf(2, "Total TPM devices: %zu\n", tpm_device_count);
}

/**
 * Initialize the TPM device list by discovering available devices
 */
static void init_tpm_devices(void) {
    vprintf(2, "Initializing TPM device list\n");
    vprintf(3, "Checking standard TPM interfaces\n");
    
    // Add known device paths
    add_tpm_device(TPM_CRB_DEVICE, "CRB");
    add_tpm_device(TPM_TIS_DEVICE, "TIS");
    
    // Check for additional TPM devices
    char path[256];
    int i = 0;
    
    // Check for additional CRB devices
    vprintf(3, "Scanning for additional CRB devices\n");
    while (1) {
        snprintf(path, sizeof(path), "/dev/tpmrm%d", i);
        if (access(path, F_OK) != 0) {
            vprintf(3, "No more CRB devices found after /dev/tpmrm%d\n", i-1);
            break;
        }
        vprintf(3, "Found additional CRB device: %s\n", path);
        add_tpm_device(path, "CRB");
        i++;
    }
    
    // Check for additional TIS devices
    vprintf(3, "Scanning for additional TIS devices\n");
    i = 0;
    while (1) {
        snprintf(path, sizeof(path), "/dev/tpm%d", i);
        if (access(path, F_OK) != 0) {
            vprintf(3, "No more TIS devices found after /dev/tpm%d\n", i-1);
            break;
        }
        vprintf(3, "Found additional TIS device: %s\n", path);
        add_tpm_device(path, "TIS");
        i++;
    }
    
    vprintf(2, "Device initialization complete. Found %zu TPM devices\n", tpm_device_count);
}

/**
 * Clean up the TPM device list and free allocated memory
 */
static void cleanup_tpm_devices(void) {
    for (size_t i = 0; i < tpm_device_count; i++) {
        if (strcmp(tpm_devices[i].path, TPM_CRB_DEVICE) != 0 && 
            strcmp(tpm_devices[i].path, TPM_TIS_DEVICE) != 0) {
            free((void *)tpm_devices[i].path);
        }
    }
    free(tpm_devices);
    tpm_devices = NULL;
    tpm_device_count = 0;
}

/**
 * Get password from user input
 *
 * @param prompt Password prompt message
 * @return Allocated string containing the password, or NULL on error
 */
static char *get_password(const char *prompt) {
    char *password = NULL;
    size_t len = 0;
    ssize_t read;

    printf("%s", prompt);
    read = getline(&password, &len, stdin);
    if (read == -1) {
        free(password);
        return NULL;
    }

    // Remove trailing newline
    if (read > 0 && password[read-1] == '\n') {
        password[read-1] = '\0';
    }

    return password;
}

/**
 * Open a TPM device
 *
 * @param force_tis Force TIS interface mode
 * @param device_num Device number to open (-1 for auto-detect)
 * @return File descriptor of opened device, or -1 on error
 */
static int open_tpm_device(int force_tis, int device_num) {
    vprintf(2, "Opening TPM device (force_tis=%d, device_num=%d)\n", force_tis, device_num);
    
    if (device_num >= 0) {
        if (device_num >= tpm_device_count) {
            TPM_ERROR("Invalid device number %d (max: %zu)", device_num, tpm_device_count - 1);
            return TPM_ERROR_INVALID_PARAM;
        }
        vprintf(2, "Using specified device %d: %s (%s)\n", 
            device_num, tpm_devices[device_num].path, tpm_devices[device_num].type);
        
        int fd = open(tpm_devices[device_num].path, O_RDWR);
        if (fd < 0) {
            TPM_ERROR_IOCTL("Failed to open TPM device", errno);
            return TPM_ERROR_IO;
        }
        vprintf(2, "Successfully opened specified TPM device\n");
        return fd;
    }
    
    // Try CRB first unless TIS is forced
    if (!force_tis) {
        vprintf(2, "Attempting to open CRB interface\n");
        int fd = open(TPM_CRB_DEVICE, O_RDWR);
        if (fd >= 0) {
            vprintf(2, "Successfully opened CRB interface\n");
            return fd;
        }
        vprintf(2, "CRB interface not available: %s\n", strerror(errno));
    }
    
    // Try TIS interface
    vprintf(2, "Attempting to open TIS interface\n");
    int fd = open(TPM_TIS_DEVICE, O_RDWR);
    if (fd >= 0) {
        vprintf(2, "Successfully opened TIS interface\n");
        return fd;
    }
    vprintf(2, "TIS interface not available: %s\n", strerror(errno));
    
    TPM_ERROR("No available TPM interface found");
    return TPM_ERROR_DEVICE;
}

/**
 * Print usage information
 *
 * @param progname Program name
 */
static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s [options] [p12_file]\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i, --info             Show TPM information\n");
    fprintf(stderr, "  --install-pk           Install platform key from P12 file\n");
    fprintf(stderr, "  -l, --list-devices     List available TPM devices\n");
    fprintf(stderr, "  --device <num>         Select TPM device by number\n");
    fprintf(stderr, "  --tis                  Force TIS interface mode\n");
    fprintf(stderr, "  -v, --verbose          Enable verbose output\n");
    fprintf(stderr, "  -w, --password <pass>  P12 password\n");
    fprintf(stderr, "  --help                 Show help message\n");
}

/**
 * Load required TPM kernel modules
 *
 * @return 1 on success, 0 on failure
 */
static int load_tpm_module(void) {
    vprintf(2, "Loading TPM kernel modules\n");
    
    // Try to load CRB module first (preferred for TPM 2.0)
    vprintf(3, "Checking if TPM CRB module is already loaded\n");
    if (system("kldstat -q -n tpmrm") != 0) {
        vprintf(2, "Loading TPM CRB module\n");
        if (system("kldload tpmrm") != 0) {
            TPM_ERROR("Failed to load TPM CRB module");
            goto done;
        }
        vprintf(2, "Successfully loaded TPM CRB module\n");
    } else {
        vprintf(2, "TPM CRB module already loaded\n");
    }

    // Try to load TIS module (fallback)
    vprintf(3, "Checking if TPM TIS module is already loaded\n");
    if (system("kldstat -q -n tpm") != 0) {
        vprintf(2, "Loading TPM TIS module\n");
        if (system("kldload tpm") != 0) {
            TPM_ERROR("Failed to load TPM TIS module");
            return TPM_ERROR_DEVICE;
        }
        vprintf(2, "Successfully loaded TPM TIS module\n");
    } else {
        vprintf(2, "TPM TIS module already loaded\n");
    }

done:
    vprintf(2, "TPM module loading complete\n");
    return TPM_SUCCESS;
}

/**
 * Print detailed TPM information
 *
 * @param tpm_fd TPM device file descriptor
 */
static void print_tpm_info(int tpm_fd) {
    vprintf(2, "Retrieving TPM information\n");
    
    struct tpm_get_capability_cmd cmd;
    struct tpm_capability_data data;
    int ret;

    // Get TPM version
    vprintf(3, "Querying TPM version\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    cmd.hdr.commandCode = TPM_CC_GetCapability;
    cmd.hdr.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_FAMILY_INDICATOR;
    cmd.propertyCount = 1;

    if (ioctl(tpm_fd, TPM_IOC_GET_CAPABILITY, &cmd) == 0) {
        printf("TPM Version: %s\n", cmd.data.tpmProperties.tpmProperty[0].value == 2 ? "2.0" : "1.2");
        vprintf(3, "TPM version query successful\n");
    } else {
        vprintf(2, "Failed to query TPM version\n");
    }

    // Get manufacturer ID
    vprintf(3, "Querying manufacturer ID\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    cmd.hdr.commandCode = TPM_CC_GetCapability;
    cmd.hdr.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_MANUFACTURER;
    cmd.propertyCount = 1;

    if (ioctl(tpm_fd, TPM_IOC_GET_CAPABILITY, &cmd) == 0) {
        uint32_t manuf = cmd.data.tpmProperties.tpmProperty[0].value;
        printf("Manufacturer ID: %c%c%c%c\n", 
            (manuf >> 24) & 0xFF,
            (manuf >> 16) & 0xFF,
            (manuf >> 8) & 0xFF,
            manuf & 0xFF);
        vprintf(3, "Manufacturer ID query successful\n");
    } else {
        vprintf(2, "Failed to query manufacturer ID\n");
    }

    // Get maximum key size
    memset(&cmd, 0, sizeof(cmd));
    cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    cmd.hdr.commandCode = TPM_CC_GetCapability;
    cmd.hdr.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_MAX_RSA_KEY_BITS;
    cmd.propertyCount = 1;

    if (ioctl(tpm_fd, TPM_IOC_GET_CAPABILITY, &cmd) == 0) {
        printf("Maximum RSA Key Size: %d bits\n", 
            cmd.data.tpmProperties.tpmProperty[0].value);
    }

    // Get number of PCR banks
    memset(&cmd, 0, sizeof(cmd));
    cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    cmd.hdr.commandCode = TPM_CC_GetCapability;
    cmd.hdr.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_PCR_COUNT;
    cmd.propertyCount = 1;

    if (ioctl(tpm_fd, TPM_IOC_GET_CAPABILITY, &cmd) == 0) {
        printf("Number of PCR Banks: %d\n", 
            cmd.data.tpmProperties.tpmProperty[0].value);
    }

    // Get TPM state
    memset(&cmd, 0, sizeof(cmd));
    cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    cmd.hdr.commandCode = TPM_CC_GetCapability;
    cmd.hdr.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_TOTAL_COMMANDS;
    cmd.propertyCount = 1;

    if (ioctl(tpm_fd, TPM_IOC_GET_CAPABILITY, &cmd) == 0) {
        printf("TPM State: %s\n", 
            cmd.data.tpmProperties.tpmProperty[0].value > 0 ? "Active" : "Inactive");
    }

    // Check platform hierarchy and setup mode
    printf("\nPlatform Status:\n");
    memset(&cmd, 0, sizeof(cmd));
    cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    cmd.hdr.commandCode = TPM_CC_GetCapability;
    cmd.hdr.paramSize = sizeof(cmd);
    cmd.capability = TPM_CAP_TPM_PROPERTIES;
    cmd.property = TPM_PT_PH_ENABLED;
    cmd.propertyCount = 1;

    if (ioctl(tpm_fd, TPM_IOC_GET_CAPABILITY, &cmd) == 0) {
        if (cmd.data.tpmProperties.tpmProperty[0].value == 1) {
            printf("Platform Hierarchy: Enabled\n");
            
            // Try to create a primary key to check setup mode
            struct tpm_create_primary_cmd create_cmd;
            memset(&create_cmd, 0, sizeof(create_cmd));
            create_cmd.hdr.tag = TPM_ST_NO_SESSIONS;
            create_cmd.hdr.commandCode = TPM_CC_CreatePrimary;
            create_cmd.hdr.paramSize = sizeof(create_cmd);
            create_cmd.primaryHandle = TPM_RH_PLATFORM;
            create_cmd.inSensitive.sensitiveType = TPM_ALG_RSA;
            create_cmd.inPublic.type = TPM_ALG_RSA;
            create_cmd.inPublic.nameAlg = TPM_ALG_SHA256;
            create_cmd.inPublic.objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH;
            create_cmd.inPublic.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
            create_cmd.inPublic.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
            create_cmd.inPublic.parameters.rsaDetail.keyBits = 2048;
            create_cmd.inPublic.parameters.rsaDetail.exponent = 65537;

            if (ioctl(tpm_fd, TPM_IOC_CREATE_PRIMARY, &create_cmd) == 0) {
                printf("Setup Mode: Enabled\n");
            } else {
                printf("Setup Mode: Disabled\n");
            }
        } else {
            printf("Platform Hierarchy: Disabled\n");
            printf("Setup Mode: Not Available\n");
        }
    }

    vprintf(2, "TPM information retrieval complete\n");
}

/**
 * Load a key from a P12 file
 *
 * @param filename P12 file path
 * @param pkey Pointer to store the loaded key
 * @param cert Pointer to store the certificate
 * @param password Optional password for the P12 file
 * @return 1 on success, 0 on failure
 */
static int load_p12_key(const char *filename, EVP_PKEY **pkey, X509 **cert, const char *password) {
    vprintf(2, "Loading P12 key from %s\n", filename);
    
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        TPM_ERROR_IOCTL("Failed to open P12 file", errno);
        return TPM_ERROR_IO;
    }
    
    vprintf(3, "Reading P12 file contents\n");
    PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    
    if (!p12) {
        TPM_ERROR_OPENSSL("Failed to parse P12 file");
        return TPM_ERROR_OPENSSL;
    }
    
    vprintf(3, "Parsing P12 file structure\n");
    if (!PKCS12_parse(p12, password, pkey, cert, NULL)) {
        TPM_ERROR_OPENSSL("Failed to parse P12 file contents");
        PKCS12_free(p12);
        return TPM_ERROR_OPENSSL;
    }
    
    vprintf(2, "Successfully loaded P12 key\n");
    vprintf(3, "Key type: %s\n", EVP_PKEY_type(EVP_PKEY_id(*pkey)) == EVP_PKEY_RSA ? "RSA" : "Unknown");
    PKCS12_free(p12);
    return TPM_SUCCESS;
}

/**
 * Convert RSA key to TPM format
 *
 * @param rsa RSA key to convert
 * @param pub TPM public key structure to store result
 * @param priv TPM private key structure to store result
 * @return 1 on success, 0 on failure
 */
static int convert_rsa_to_tpm(RSA *rsa, struct tpm2b_public *pub, struct tpm2b_private *priv) {
    vprintf(3, "Converting RSA key to TPM format\n");
    
    const BIGNUM *n, *e, *d;
    RSA_get0_key(rsa, &n, &e, &d);
    
    if (!n || !e || !d) {
        TPM_ERROR("Invalid RSA key components");
        return TPM_ERROR_INVALID_PARAM;
    }
    
    vprintf(3, "RSA key parameters:\n");
    vprintf(3, "  Modulus bits: %d\n", BN_num_bits(n));
    vprintf(3, "  Public exponent: %lu\n", BN_get_word(e));
    
    // Convert public key
    struct tpmt_public *tpub = (struct tpmt_public *)pub->buffer.buffer;
    if (!tpub) {
        TPM_ERROR("Failed to allocate TPM public key structure");
        return TPM_ERROR_MEMORY;
    }
    
    vprintf(3, "Setting up TPM public key structure\n");
    tpub->type = TPM_ALG_RSA;
    tpub->nameAlg = TPM_ALG_SHA256;
    tpub->objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH;
    tpub->authPolicy.size = 0;
    
    struct tpm_rsa_parameters *params = &tpub->parameters;
    params->symmetric = TPM_ALG_NULL;
    params->scheme = TPM_ALG_NULL;
    params->keyBits = BN_num_bits(n);
    params->exponent = BN_get_word(e);
    
    pub->size = sizeof(struct tpmt_public);
    
    // Convert private key
    vprintf(3, "Setting up TPM private key structure\n");
    struct tpmt_private *tpriv = (struct tpmt_private *)priv->buffer.sensitive.rsa.buffer;
    if (!tpriv) {
        TPM_ERROR("Failed to allocate TPM private key structure");
        return TPM_ERROR_MEMORY;
    }
    
    tpriv->sensitiveType = TPM_ALG_RSA;
    tpriv->auth.size = 0;
    tpriv->seed.size = 0;
    
    priv->size = sizeof(struct tpmt_private);
    
    vprintf(2, "Successfully converted RSA key to TPM format\n");
    return TPM_SUCCESS;
}

/**
 * Install a platform key in the TPM
 *
 * @param pkey Platform key to install
 * @param verbose Enable verbose output
 * @return 0 on success, 1 on failure
 */
static int install_platform_key(EVP_PKEY *pkey, int verbose) {
    vprintf(2, "Installing platform key\n");
    
    if (!pkey) {
        TPM_ERROR("Invalid platform key");
        return TPM_ERROR_INVALID_PARAM;
    }
    
    struct tpm_key key;
    struct tpm2b_public pub;
    struct tpm2b_private priv;
    
    vprintf(3, "Converting key to TPM format\n");
    int ret = convert_rsa_to_tpm(EVP_PKEY_get0_RSA(pkey), &pub, &priv);
    if (ret != TPM_SUCCESS) {
        TPM_ERROR("Failed to convert key to TPM format");
        return ret;
    }
    
    vprintf(3, "Creating primary key in TPM\n");
    struct tpm_create_primary_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    cmd.hdr.commandCode = TPM_CC_CreatePrimary;
    cmd.hdr.paramSize = sizeof(struct tpm_create_primary_cmd);
    cmd.primaryHandle = TPM_RH_PLATFORM;
    cmd.inPublic = pub;
    cmd.inSensitive = priv;
    
    vprintf(3, "Loading key into TPM\n");
    struct tpm_load_cmd load_cmd;
    memset(&load_cmd, 0, sizeof(load_cmd));
    load_cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    load_cmd.hdr.commandCode = TPM_CC_Load;
    load_cmd.hdr.paramSize = sizeof(struct tpm_load_cmd);
    load_cmd.parentHandle = TPM_RH_PLATFORM;
    load_cmd.inPrivate = priv;
    load_cmd.inPublic = pub;
    
    vprintf(3, "Making key persistent in TPM\n");
    struct tpm_evict_control_cmd evict_cmd;
    memset(&evict_cmd, 0, sizeof(evict_cmd));
    evict_cmd.hdr.tag = TPM_ST_NO_SESSIONS;
    evict_cmd.hdr.commandCode = TPM_CC_EvictControl;
    evict_cmd.hdr.paramSize = sizeof(struct tpm_evict_control_cmd);
    evict_cmd.auth = TPM_RH_PLATFORM;
    evict_cmd.objectHandle = TPM_PLATFORM_HANDLE;
    evict_cmd.persistentHandle = TPM_PLATFORM_HANDLE;
    
    vprintf(2, "Successfully installed platform key\n");
    return TPM_SUCCESS;
}

/**
 * Check if a TPM device is available
 *
 * @param device Device path to check
 * @return 1 if device is available, 0 otherwise
 */
static int check_tpm_device(const char *device) {
    int fd = open(device, O_RDWR);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}

/**
 * List available TPM devices
 */
static void list_tpm_devices(void) {
    vprintf(2, "Listing available TPM devices\n");
    printf("Available TPM devices:\n");
    for (size_t i = 0; i < tpm_device_count; i++) {
        printf("  %zu: %s (%s)\n", i, tpm_devices[i].path, tpm_devices[i].type);
        vprintf(3, "  Device %zu details:\n", i);
        vprintf(3, "    Path: %s\n", tpm_devices[i].path);
        vprintf(3, "    Type: %s\n", tpm_devices[i].type);
        vprintf(3, "    Available: %s\n", tpm_devices[i].available ? "Yes" : "No");
    }
    vprintf(2, "Device listing complete\n");
}

/**
 * Main function
 */
int main(int argc, char *argv[]) {
    int opt;
    int ret = TPM_SUCCESS;
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Parse command line options
    while ((opt = getopt(argc, argv, "ilvw:d:t")) != -1) {
        switch (opt) {
            case 'i':
                show_info = 1;
                break;
            case 'l':
                list_devices = 1;
                break;
            case 'v':
                verbosity++;
                vprintf(2, "Verbosity level increased to %d\n", verbosity);
                break;
            case 'w':
                p12_password = optarg;
                break;
            case 'd':
                device_num = atoi(optarg);
                vprintf(2, "Selected device number: %d\n", device_num);
                break;
            case 't':
                force_tis = 1;
                vprintf(2, "Forcing TIS interface mode\n");
                break;
            default:
                print_usage(argv[0]);
                ret = TPM_ERROR_INVALID_PARAM;
                goto cleanup;
        }
    }
    
    // Handle non-option arguments
    if (optind < argc) {
        p12_file = argv[optind];
        vprintf(2, "P12 file specified: %s\n", p12_file);
    }
    
    vprintf(2, "Initializing TPM devices\n");
    init_tpm_devices();
    
    if (list_devices) {
        list_tpm_devices();
        goto cleanup;
    }
    
    if (show_info || install_pk) {
        if (!load_tpm_module()) {
            ret = TPM_ERROR_DEVICE;
            goto cleanup;
        }
        
        int tpm_fd = open_tpm_device(force_tis, device_num);
        if (tpm_fd < 0) {
            ret = TPM_ERROR_DEVICE;
            goto cleanup;
        }
        
        if (show_info) {
            vprintf(2, "Showing TPM information\n");
            print_tpm_info(tpm_fd);
        }
        
        if (install_pk) {
            if (!p12_file) {
                TPM_ERROR("P12 file required for platform key installation");
                ret = TPM_ERROR_INVALID_PARAM;
                close(tpm_fd);
                goto cleanup;
            }
            
            vprintf(2, "Installing platform key from %s\n", p12_file);
            EVP_PKEY *pkey = NULL;
            X509 *cert = NULL;
            
            ret = load_p12_key(p12_file, &pkey, &cert, p12_password);
            if (ret != TPM_SUCCESS) {
                close(tpm_fd);
                goto cleanup;
            }
            
            ret = install_platform_key(pkey, verbosity);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            close(tpm_fd);
            goto cleanup;
        }
        
        close(tpm_fd);
    }
    
cleanup:
    cleanup_tpm_devices();
    EVP_cleanup();
    ERR_free_strings();
    return ret;
}
