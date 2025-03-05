/*
 * efi-sign - EFI/PE Executable Signing Utility
 *
 * This utility provides command-line interface for signing and managing
 * signatures on EFI/PE executables.
 *
 * Features:
 * - Sign PE executables using P12 keys
 * - Verify existing signatures
 * - Clear existing signatures
 * - Support for both 32-bit and 64-bit PE files
 * - Password-protected P12 file support
 *
 * Usage:
 *   efi-sign [options] <p12_file> <input_file>
 *
 * Options:
 *   -s, --sign           Sign the file (default if no other option specified)
 *   -c, --clear         Clear existing signature
 *   -v, --verify       Verify existing signature
 *   -w, --password <pass> P12 password
 *   -y, --yes          Skip confirmation prompts
 *   --help             Show help message
 *
 * Note: P12 file is required for both signing and verification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

/* PE file structures */
#define PE_SIGNATURE 0x4550  /* "PE" signature */
#define IMAGE_DOS_SIGNATURE 0x5A4D  /* "MZ" signature */

struct dos_header {
    uint16_t e_magic;      /* Magic number */
    uint16_t e_cblp;       /* Bytes on last page of file */
    uint16_t e_cp;         /* Pages in file */
    uint16_t e_crlc;       /* Relocations */
    uint16_t e_cparhdr;    /* Size of header in paragraphs */
    uint16_t e_minalloc;   /* Minimum extra paragraphs needed */
    uint16_t e_maxalloc;   /* Maximum extra paragraphs needed */
    uint16_t e_ss;         /* Initial (relative) SS value */
    uint16_t e_sp;         /* Initial SP value */
    uint16_t e_csum;       /* Checksum */
    uint16_t e_ip;         /* Initial IP value */
    uint16_t e_cs;         /* Initial (relative) CS value */
    uint16_t e_lfarlc;     /* File address of relocation table */
    uint16_t e_ovno;       /* Overlay number */
    uint16_t e_res[4];     /* Reserved words */
    uint16_t e_oemid;      /* OEM identifier */
    uint16_t e_oeminfo;    /* OEM information */
    uint16_t e_res2[10];   /* Reserved words */
    uint32_t e_lfanew;     /* File address of new exe header */
};

struct pe_header {
    uint32_t signature;    /* PE signature */
    uint16_t machine;      /* Machine type */
    uint16_t num_sections; /* Number of sections */
    uint32_t timestamp;    /* Time/date stamp */
    uint32_t symbol_table; /* Symbol table pointer */
    uint32_t num_symbols;  /* Number of symbols */
    uint16_t opt_header_size; /* Size of optional header */
    uint16_t characteristics; /* File characteristics */
};

struct pe_optional_header {
    uint16_t magic;        /* Magic number */
    uint8_t major_linker;  /* Major linker version */
    uint8_t minor_linker;  /* Minor linker version */
    uint32_t code_size;    /* Size of code section */
    uint32_t init_data_size; /* Size of initialized data */
    uint32_t uninit_data_size; /* Size of uninitialized data */
    uint32_t entry_point;  /* Entry point */
    uint32_t code_base;    /* Base of code */
    uint32_t data_base;    /* Base of data */
    uint32_t image_base;   /* Image base */
    uint32_t section_align; /* Section alignment */
    uint32_t file_align;   /* File alignment */
    uint16_t major_os;     /* Major OS version */
    uint16_t minor_os;     /* Minor OS version */
    uint16_t major_image;  /* Major image version */
    uint16_t minor_image;  /* Minor image version */
    uint16_t major_subsys; /* Major subsystem version */
    uint16_t minor_subsys; /* Minor subsystem version */
    uint32_t reserved;     /* Reserved */
    uint32_t image_size;   /* Size of image */
    uint32_t headers_size; /* Size of headers */
    uint32_t checksum;     /* Checksum */
    uint16_t subsystem;    /* Subsystem */
    uint16_t dll_characteristics; /* DLL characteristics */
    uint32_t stack_reserve_size; /* Stack reserve size */
    uint32_t stack_commit_size;  /* Stack commit size */
    uint32_t heap_reserve_size;  /* Heap reserve size */
    uint32_t heap_commit_size;   /* Heap commit size */
    uint32_t loader_flags;       /* Loader flags */
    uint32_t num_rva_sizes;      /* Number of RVA and sizes */
};

struct pe_section_header {
    char name[8];          /* Section name */
    uint32_t virtual_size; /* Virtual size */
    uint32_t virtual_addr; /* Virtual address */
    uint32_t raw_size;     /* Size of raw data */
    uint32_t raw_ptr;      /* Pointer to raw data */
    uint32_t reloc_ptr;    /* Pointer to relocations */
    uint32_t line_num_ptr; /* Pointer to line numbers */
    uint16_t num_relocs;   /* Number of relocations */
    uint16_t num_lines;    /* Number of line numbers */
    uint32_t characteristics; /* Section characteristics */
};

struct pe_data_directory {
    uint32_t rva;          /* Relative virtual address */
    uint32_t size;         /* Size */
};

/* Global variables */
static int verbose = 0;
static int clear_signature = 0;
static int verify_signature = 0;
static int sign_file = 0;
static int skip_confirm = 0;
static const char *p12_password = NULL;

/**
 * Print verbose message based on verbosity level
 *
 * @param level Required verbosity level (1-3)
 * @param fmt Format string
 * @param ... Format arguments
 */
static void vprintf(int level, const char *fmt, ...) {
    if (verbose >= level) {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
}

/**
 * Print usage information
 *
 * @param progname Program name
 */
static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s [options] <p12_file> <input_file>\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -s, --sign           Sign the file (default if no other option specified)\n");
    fprintf(stderr, "  -c, --clear         Clear existing signature\n");
    fprintf(stderr, "  -v, --verify       Verify existing signature\n");
    fprintf(stderr, "  -w, --password <pass> P12 password\n");
    fprintf(stderr, "  -y, --yes          Skip confirmation prompts\n");
    fprintf(stderr, "  --help             Show help message\n");
    fprintf(stderr, "\nNote: P12 file is required for both signing and verification.\n");
}

/**
 * Get user confirmation
 *
 * @param prompt The confirmation prompt to display
 * @return 1 if confirmed, 0 if not confirmed
 */
static int get_confirmation(const char *prompt) {
    if (skip_confirm) {
        return 1;
    }

    char response[4];
    printf("%s (y/N): ", prompt);
    if (fgets(response, sizeof(response), stdin) == NULL) {
        return 0;
    }

    // Remove trailing newline
    size_t len = strlen(response);
    if (len > 0 && response[len-1] == '\n') {
        response[len-1] = '\0';
    }

    return (strcasecmp(response, "y") == 0 || strcasecmp(response, "yes") == 0);
}

/**
 * Load a key from a P12 file
 *
 * @param filename P12 file path
 * @param pkey Pointer to store the loaded key
 * @param cert Pointer to store the certificate
 * @return 1 on success, 0 on failure
 */
static int load_p12_key(const char *filename, EVP_PKEY **pkey, X509 **cert) {
    vprintf(2, "Opening P12 file: %s\n", filename);
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open P12 file: %s\n", filename);
        return 0;
    }

    vprintf(3, "Parsing P12 file...\n");
    PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) {
        fprintf(stderr, "Failed to parse P12 file\n");
        return 0;
    }

    // Try to parse without password first
    vprintf(3, "Attempting to parse without password...\n");
    if (PKCS12_parse(p12, NULL, pkey, cert, NULL)) {
        vprintf(2, "Successfully loaded P12 file without password\n");
        PKCS12_free(p12);
        return 1;
    }

    // If no password worked and a password was provided, try that
    if (p12_password) {
        vprintf(3, "Attempting to parse with provided password...\n");
        if (PKCS12_parse(p12, p12_password, pkey, cert, NULL)) {
            vprintf(2, "Successfully loaded P12 file with provided password\n");
            PKCS12_free(p12);
            return 1;
        }
    }

    // If still no success, prompt for password
    vprintf(3, "Prompting for password...\n");
    char *prompt_password = NULL;
    size_t len = 0;
    ssize_t read;

    printf("Enter P12 password: ");
    read = getline(&prompt_password, &len, stdin);
    if (read == -1) {
        free(prompt_password);
        PKCS12_free(p12);
        return 0;
    }

    // Remove trailing newline
    if (read > 0 && prompt_password[read-1] == '\n') {
        prompt_password[read-1] = '\0';
    }

    vprintf(3, "Attempting to parse with entered password...\n");
    int ret = PKCS12_parse(p12, prompt_password, pkey, cert, NULL);
    free(prompt_password);
    PKCS12_free(p12);
    
    if (ret) {
        vprintf(2, "Successfully loaded P12 file with entered password\n");
    } else {
        vprintf(2, "Failed to load P12 file with entered password\n");
    }
    
    return ret;
}

/**
 * Find the PE signature directory in a PE file
 *
 * @param data File data
 * @param size File size
 * @param dir Pointer to store directory information
 * @return 1 if found, 0 otherwise
 */
static int find_pe_signature(const uint8_t *data, size_t size, struct pe_data_directory *dir) {
    vprintf(3, "Checking DOS header...\n");
    struct dos_header *dos = (struct dos_header *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        vprintf(2, "Invalid DOS signature\n");
        return 0;
    }
    vprintf(3, "DOS header:\n");
    vprintf(3, "  Magic: 0x%04x\n", dos->e_magic);
    vprintf(3, "  PE header offset: 0x%x\n", dos->e_lfanew);

    vprintf(3, "Checking PE header...\n");
    struct pe_header *pe = (struct pe_header *)(data + dos->e_lfanew);
    if (pe->signature != PE_SIGNATURE) {
        vprintf(2, "Invalid PE signature\n");
        return 0;
    }
    vprintf(3, "PE header:\n");
    vprintf(3, "  Signature: 0x%08x\n", pe->signature);
    vprintf(3, "  Machine: 0x%04x\n", pe->machine);
    vprintf(3, "  Number of sections: %d\n", pe->num_sections);
    vprintf(3, "  Optional header size: %d\n", pe->opt_header_size);
    vprintf(3, "  Characteristics: 0x%04x\n", pe->characteristics);

    vprintf(3, "Finding signature directory...\n");
    struct pe_optional_header *opt = (struct pe_optional_header *)((uint8_t *)pe + sizeof(struct pe_header));
    vprintf(3, "Optional header:\n");
    vprintf(3, "  Magic: 0x%04x\n", opt->magic);
    vprintf(3, "  Image base: 0x%08x\n", opt->image_base);
    vprintf(3, "  Section alignment: 0x%08x\n", opt->section_align);
    vprintf(3, "  File alignment: 0x%08x\n", opt->file_align);
    vprintf(3, "  Size of image: 0x%08x\n", opt->image_size);
    vprintf(3, "  Size of headers: 0x%08x\n", opt->headers_size);
    vprintf(3, "  Checksum: 0x%08x\n", opt->checksum);
    vprintf(3, "  Subsystem: 0x%04x\n", opt->subsystem);
    vprintf(3, "  DLL characteristics: 0x%04x\n", opt->dll_characteristics);

    struct pe_data_directory *dirs = (struct pe_data_directory *)((uint8_t *)opt + opt->opt_header_size - sizeof(struct pe_data_directory) * 16);
    
    // The signature directory is the last entry
    *dir = dirs[15];
    vprintf(3, "Signature directory:\n");
    vprintf(3, "  RVA: 0x%08x\n", dir->rva);
    vprintf(3, "  Size: %u bytes\n", dir->size);
    return 1;
}

/**
 * Clear an existing PE signature
 *
 * @param data File data
 * @param size File size
 * @return 1 on success, 0 on failure
 */
static int clear_pe_signature(uint8_t *data, size_t size) {
    vprintf(2, "Checking for existing signature...\n");
    struct pe_data_directory dir;
    if (!find_pe_signature(data, size, &dir)) {
        fprintf(stderr, "Error: Not a valid PE file\n");
        return 0;
    }

    if (dir.rva == 0 || dir.size == 0) {
        fprintf(stderr, "Error: File has no signature to clear\n");
        return 0;
    }

    vprintf(2, "Found signature at RVA 0x%x, size %u bytes\n", dir.rva, dir.size);
    vprintf(3, "Zeroing signature directory...\n");

    // Zero out the signature directory
    struct dos_header *dos = (struct dos_header *)data;
    struct pe_header *pe = (struct pe_header *)(data + dos->e_lfanew);
    struct pe_optional_header *opt = (struct pe_optional_header *)((uint8_t *)pe + sizeof(struct pe_header));
    struct pe_data_directory *dirs = (struct pe_data_directory *)((uint8_t *)opt + opt->opt_header_size - sizeof(struct pe_data_directory) * 16);
    
    vprintf(3, "Before clearing:\n");
    vprintf(3, "  Signature directory RVA: 0x%08x\n", dirs[15].rva);
    vprintf(3, "  Signature directory size: %u bytes\n", dirs[15].size);
    
    dirs[15].rva = 0;
    dirs[15].size = 0;
    
    vprintf(3, "After clearing:\n");
    vprintf(3, "  Signature directory RVA: 0x%08x\n", dirs[15].rva);
    vprintf(3, "  Signature directory size: %u bytes\n", dirs[15].size);

    vprintf(2, "Signature directory cleared\n");
    return 1;
}

/**
 * Verify a PE signature
 *
 * @param data File data
 * @param size File size
 * @return 1 if signature is valid, 0 otherwise
 */
static int verify_pe_signature(const uint8_t *data, size_t size) {
    vprintf(2, "Checking for existing signature...\n");
    struct pe_data_directory dir;
    if (!find_pe_signature(data, size, &dir)) {
        fprintf(stderr, "No PE signature found\n");
        return 0;
    }

    if (dir.rva == 0 || dir.size == 0) {
        fprintf(stderr, "No signature to verify\n");
        return 0;
    }

    vprintf(2, "Found signature at RVA 0x%x, size %u bytes\n", dir.rva, dir.size);
    vprintf(3, "Reading signature data...\n");

    // Get the signature data
    const uint8_t *sig_data = data + dir.rva;
    PKCS7 *p7 = d2i_PKCS7(NULL, &sig_data, dir.size);
    if (!p7) {
        fprintf(stderr, "Failed to parse signature\n");
        return 0;
    }

    vprintf(3, "Verifying signature...\n");
    // Verify the signature
    int ret = PKCS7_verify(p7, NULL, NULL, NULL, NULL, 0);
    PKCS7_free(p7);

    if (ret) {
        printf("Signature is valid\n");
        vprintf(2, "Signature verification successful\n");
    } else {
        printf("Signature is invalid\n");
        vprintf(2, "Signature verification failed\n");
    }

    return ret;
}

/**
 * Sign a PE file
 *
 * @param data File data
 * @param size File size
 * @param pkey Signing key
 * @param cert Signing certificate
 * @return 1 on success, 0 on failure
 */
static int sign_pe_file(uint8_t *data, size_t size, EVP_PKEY *pkey, X509 *cert) {
    vprintf(2, "Calculating file hash...\n");
    // Calculate hash of the file
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, size);
    SHA256_Final(hash, &ctx);
    vprintf(3, "File hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        vprintf(3, "%02x", hash[i]);
    }
    vprintf(3, "\n");

    vprintf(3, "Creating PKCS7 structure...\n");
    // Create PKCS7 structure
    PKCS7 *p7 = PKCS7_new();
    if (!p7) {
        fprintf(stderr, "Failed to create PKCS7 structure\n");
        return 0;
    }

    vprintf(3, "Setting up signer info...\n");
    // Add the signer info
    PKCS7_SIGNER_INFO *si = PKCS7_SIGNER_INFO_new();
    if (!si) {
        PKCS7_free(p7);
        return 0;
    }

    // Set up the signer info
    si->version = ASN1_INTEGER_new();
    ASN1_INTEGER_set(si->version, 1);

    // Add the certificate
    si->cert = cert;

    // Add the digest algorithm
    si->digest_alg = X509_ALGOR_new();
    si->digest_alg->algorithm = OBJ_nid2obj(NID_sha256);
    si->digest_alg->parameter = ASN1_TYPE_new();
    si->digest_alg->parameter->type = V_ASN1_NULL;

    // Add the signature
    si->digest_enc_alg = X509_ALGOR_new();
    si->digest_enc_alg->algorithm = OBJ_nid2obj(NID_rsaEncryption);
    si->digest_enc_alg->parameter = ASN1_TYPE_new();
    si->digest_enc_alg->parameter->type = V_ASN1_NULL;

    vprintf(3, "Signing hash...\n");
    // Sign the hash
    unsigned char *sig = NULL;
    unsigned int sig_len = 0;
    if (!RSA_sign(NID_sha256, hash, sizeof(hash), &sig, &sig_len, EVP_PKEY_get1_RSA(pkey))) {
        PKCS7_SIGNER_INFO_free(si);
        PKCS7_free(p7);
        return 0;
    }

    si->enc_digest = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(si->enc_digest, sig, sig_len);
    free(sig);

    // Add the signer info to the PKCS7 structure
    sk_PKCS7_SIGNER_INFO_push(p7->d.sign->signer_info, si);

    vprintf(3, "Converting to DER format...\n");
    // Convert to DER
    unsigned char *der = NULL;
    int der_len = i2d_PKCS7(p7, &der);
    if (der_len <= 0) {
        PKCS7_free(p7);
        return 0;
    }

    vprintf(2, "Adding signature to PE file (size: %d bytes)...\n", der_len);
    // Add the signature to the PE file
    struct dos_header *dos = (struct dos_header *)data;
    struct pe_header *pe = (struct pe_header *)(data + dos->e_lfanew);
    struct pe_optional_header *opt = (struct pe_optional_header *)((uint8_t *)pe + sizeof(struct pe_header));
    struct pe_data_directory *dirs = (struct pe_data_directory *)((uint8_t *)opt + opt->opt_header_size - sizeof(struct pe_data_directory) * 16);

    // Find a suitable location for the signature
    uint32_t sig_rva = size;
    uint32_t sig_size = der_len;

    vprintf(3, "Before adding signature:\n");
    vprintf(3, "  Signature directory RVA: 0x%08x\n", dirs[15].rva);
    vprintf(3, "  Signature directory size: %u bytes\n", dirs[15].size);
    vprintf(3, "  New signature RVA: 0x%08x\n", sig_rva);
    vprintf(3, "  New signature size: %u bytes\n", sig_size);

    // Update the signature directory
    dirs[15].rva = sig_rva;
    dirs[15].size = sig_size;

    vprintf(3, "After updating directory:\n");
    vprintf(3, "  Signature directory RVA: 0x%08x\n", dirs[15].rva);
    vprintf(3, "  Signature directory size: %u bytes\n", dirs[15].size);

    vprintf(3, "Writing signature at RVA 0x%x\n", sig_rva);
    // Append the signature to the file
    memcpy(data + sig_rva, der, sig_size);
    free(der);
    PKCS7_free(p7);

    vprintf(2, "Signature added successfully\n");
    return 1;
}

/**
 * Main function
 */
int main(int argc, char *argv[]) {
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    const char *p12_file = NULL;
    const char *input_file = NULL;
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    int ret = 1;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sign") == 0) {
            sign_file = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--clear") == 0) {
            clear_signature = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verify") == 0) {
            verify_signature = 1;
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--password") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Missing password value\n");
                print_usage(argv[0]);
                return 1;
            }
            p12_password = argv[i];
        } else if (strcmp(argv[i], "-y") == 0 || strcmp(argv[i], "--yes") == 0) {
            skip_confirm = 1;
        } else if (strncmp(argv[i], "-v", 2) == 0) {
            // Count number of v's for verbosity level
            int v_count = 0;
            const char *p = argv[i];
            while (*p == 'v') {
                v_count++;
                p++;
            }
            if (*p == '\0') {
                verbose = v_count;
            } else {
                fprintf(stderr, "Unknown option: %s\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (!p12_file) {
            p12_file = argv[i];
        } else if (!input_file) {
            input_file = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    vprintf(1, "Verbosity level: %d\n", verbose);
    vprintf(2, "Operation: %s\n", sign_file ? "Sign" : (clear_signature ? "Clear" : (verify_signature ? "Verify" : "Unknown")));
    vprintf(2, "Input file: %s\n", input_file);
    if (p12_file) {
        vprintf(2, "P12 file: %s\n", p12_file);
    }

    // Check required arguments
    if (!input_file) {
        fprintf(stderr, "Input file required\n");
        print_usage(argv[0]);
        return 1;
    }

    // If no operation specified, default to signing
    if (!sign_file && !clear_signature && !verify_signature) {
        sign_file = 1;
    }

    if (!p12_file && (verify_signature || sign_file)) {
        fprintf(stderr, "P12 file required for this operation\n");
        print_usage(argv[0]);
        return 1;
    }

    // Read input file
    vprintf(2, "Reading input file...\n");
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open input file: %s\n", input_file);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    vprintf(2, "File size: %zu bytes\n", file_size);

    file_data = malloc(file_size);
    if (!file_data) {
        fprintf(stderr, "Failed to allocate memory\n");
        fclose(fp);
        return 1;
    }

    if (fread(file_data, 1, file_size, fp) != file_size) {
        fprintf(stderr, "Failed to read input file\n");
        free(file_data);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    // Initialize OpenSSL
    vprintf(2, "Initializing OpenSSL...\n");
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // If verifying signature
    if (verify_signature) {
        vprintf(2, "Loading P12 key for verification...\n");
        // Load the P12 key for verification
        if (!load_p12_key(p12_file, &pkey, &cert)) {
            fprintf(stderr, "Failed to load P12 key\n");
            goto cleanup;
        }
        vprintf(2, "Verifying signature...\n");
        ret = verify_pe_signature(file_data, file_size);
        goto cleanup;
    }

    // If clearing signature
    if (clear_signature) {
        vprintf(2, "Checking for existing signature...\n");
        ret = clear_pe_signature(file_data, file_size);
        if (ret) {
            if (!get_confirmation("Are you sure you want to clear the signature?")) {
                printf("Operation cancelled\n");
                goto cleanup;
            }

            vprintf(2, "Writing modified file...\n");
            // Write modified file back to original location
            fp = fopen(input_file, "wb");
            if (!fp) {
                fprintf(stderr, "Failed to open file for writing: %s\n", input_file);
                goto cleanup;
            }
            if (fwrite(file_data, 1, file_size, fp) != file_size) {
                fprintf(stderr, "Failed to write file\n");
                fclose(fp);
                goto cleanup;
            }
            fclose(fp);
            printf("Signature cleared successfully\n");
        }
        // Return error if no signature was found
        if (!ret) {
            ret = 1;
        }
        goto cleanup;
    }

    // If signing file
    if (!p12_file) {
        fprintf(stderr, "P12 file required for signing\n");
        print_usage(argv[0]);
        goto cleanup;
    }

    // Load the P12 key
    vprintf(2, "Loading P12 key for signing...\n");
    if (!load_p12_key(p12_file, &pkey, &cert)) {
        fprintf(stderr, "Failed to load P12 key\n");
        goto cleanup;
    }

    // Get confirmation for signing
    if (!get_confirmation("Are you sure you want to sign the file?")) {
        printf("Operation cancelled\n");
        goto cleanup;
    }

    vprintf(2, "Signing file...\n");
    // Sign the file
    if (!sign_pe_file(file_data, file_size, pkey, cert)) {
        fprintf(stderr, "Failed to sign file\n");
        goto cleanup;
    }

    vprintf(2, "Writing signed file...\n");
    // Write signed file back to original location
    fp = fopen(input_file, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open file for writing: %s\n", input_file);
        goto cleanup;
    }
    if (fwrite(file_data, 1, file_size, fp) != file_size) {
        fprintf(stderr, "Failed to write file\n");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    printf("File signed successfully\n");
    ret = 0;

cleanup:
    vprintf(2, "Cleaning up...\n");
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (file_data) free(file_data);

    EVP_cleanup();
    ERR_free_strings();

    return ret;
}
