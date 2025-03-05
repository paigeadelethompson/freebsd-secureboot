# FreeBSD Secure Boot

This repository contains tools and utilities for managing secure boot on FreeBSD systems.

## Introduction

Secure Boot is a UEFI feature that ensures only trusted software can boot the system. By default, most systems come with Microsoft's UEFI Certificate Authority (CA) pre-installed, which allows booting Windows and other Microsoft-signed operating systems. However, this default setup doesn't provide the level of security many users need, as it only verifies against Microsoft's certificate.

### Platform Setup Mode

Platform Setup Mode is a special TPM state that allows platform owners to take control of their system's security. When enabled, it allows you to:
- Install your own platform key
- Clear the TPM
- Manage platform hierarchy authorization
- Configure secure boot policies

This mode is typically enabled by default on new systems or can be enabled through UEFI settings. It's crucial for taking ownership of your system's security.

### The Microsoft Dependency Problem

Most systems today rely on Microsoft's UEFI Certificate Authority (CA) for secure boot. This means:
- Your system's security is tied to Microsoft's certificate
- You're dependent on Microsoft's key management
- You can't fully control your system's security
- You're limited to Microsoft's security policies

While tools like `mokutil` and shims exist to work within this system, they don't solve the fundamental issue of Microsoft's control over your system's security. They're workarounds rather than true solutions.

### The FreeBSD Approach

While FreeBSD may eventually support `mokutil`-style tools, this direct TPM programming approach offers several advantages:
- No dependency on Microsoft's certificate
- Single-step platform key installation

The tools in this repository make it easy to:
1. Take ownership of your system's security
2. Install your own platform key
3. Manage TPM settings
4. Configure secure boot policies

This approach gives you complete control over your system's security without relying on third-party certificates or complex key management schemes. It's particularly valuable for users who want full control over their system's security, regardless of future FreeBSD secure boot developments.

## Components

### EFI Platform Key Installer (`pkinstall`)

The `pkinstall` EFI application is designed to manage TPM platform keys during EFI runtime. It provides the following features:

- Show detailed TPM information:
  - TPM version and manufacturer
  - Maximum RSA key size
  - Number of PCR banks
  - Platform hierarchy status
  - Setup mode status
  - Auth settings for all hierarchies

- Clear TPM functionality:
  - Requires platform hierarchy to be enabled
  - Requires user confirmation
  - Resets TPM to factory state

- Platform key installation:
  - Supports P12 file format
  - Password-protected P12 support
  - Direct TPM programming
  - Support for both TPM 1.2 and 2.0

#### Purpose and Advantages

This tool serves as a reliable alternative to problematic UEFI firmware implementations and OS-level TPM management tools. Many modern systems, particularly certain Dell, Lenovo, and other OEM systems, have buggy or cumbersome UEFI interfaces for TPM management. Additionally, some operating systems' TPM management tools may not work correctly with specific hardware configurations.

Key advantages:
- Direct EFI runtime operation, bypassing OS-level issues
- No dependency on potentially problematic UEFI firmware interfaces
- Support for password-protected P12 files (unlike some alternatives that only support unencrypted DER certificates)
- Works with standard FAT filesystems without special requirements
- Designed specifically for FreeBSD's secure boot ecosystem

This tool is particularly useful as a backup solution when standard TPM management methods fail or are impractical to use.

#### Usage Examples

Show TPM information:
```bash
pkinstall.efi -i
```

Clear TPM (requires confirmation):
```bash
pkinstall.efi --clear
```

Install platform key from P12 file:
```bash
pkinstall.efi -k platform_key.p12
```

Install password-protected platform key:
```bash
pkinstall.efi -k platform_key.p12 mypassword
```

Show detailed TPM information with verbose output:
```bash
pkinstall.efi -v -i
```

#### Security Considerations

- The clear TPM operation is destructive and cannot be undone. It should only be performed when absolutely necessary and with proper authorization.
- Platform key installation should only be performed when the TPM is in platform setup mode and with proper authorization.
- The application requires platform hierarchy to be enabled for most operations.

### TPM Control Utility (`tpmctl`)

The `tpmctl` utility provides a command-line interface for managing TPM devices on FreeBSD systems. It supports:

- Listing available TPM devices
- Showing TPM status and information
- Clearing TPM (when in platform setup mode)
- Installing platform keys from P12 files

#### Usage Examples

List TPM devices:
```bash
tpmctl -l
```

Show TPM information:
```bash
tpmctl -i
```

Clear TPM:
```bash
tpmctl --clear
```

Install platform key:
```bash
tpmctl -k platform_key.p12 [password]
```

## Building

To build the components:

```bash
make
```

This will build both the EFI application and the TPM control utility.

## Installation

The built components can be installed using:

```bash
make install
```

## Documentation

For detailed documentation, see the man pages:
- `pkinstall(8)` - EFI Platform Key Installer
- `tpmctl(8)` - TPM Control Utility

## TODO

- Testing and Validation:
  - `keyctl` to generate the PK p12, but in general FreeBSD could benefit from a system keyring, module signing, and measured/trusted boot (liek IMA/EVM or Windows Defender Application Control / Applocker.)
  - Need to test on various TPM 1.2 and 2.0 hardware
  - Need to verify P12 file parsing with different key formats
  - Need to test error handling and recovery scenarios
  - Need to verify platform hierarchy operations
  - Need to test with different EFI firmware implementations

- Test Cases:
  - Create unit tests for TPM command structures
  - Create integration tests for EFI runtime operations
  - Create test cases for P12 file parsing
  - Create test cases for error conditions
  - Create test cases for platform hierarchy operations
  - Create test cases for security boundary conditions

## References

- TCG EFI Protocol Specification (TPM 2.0)
  - https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/
  - TCG published specification for EFI TPM 2.0 protocol

- UEFI Specification
  - https://uefi.org/specifications
  - UEFI Platform Initialization Specification

- TPM 2.0 Library Specification
  - https://trustedcomputinggroup.org/resource/tpm-library-specification/
  - TCG TPM 2.0 Library Specification

- FreeBSD TPM Documentation
  - https://www.freebsd.org/doc/en/articles/efi/
  - FreeBSD EFI and TPM documentation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the BSD 3-Clause License - see the LICENSE file for details. 