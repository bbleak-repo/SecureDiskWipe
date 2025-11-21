# SecureDiskWipe

A comprehensive, defensive security tool for securely deleting files and folders with advanced anti-forensics capabilities.

## Overview

SecureDiskWipe goes beyond simple file deletion by implementing multiple layers of security:

- **Content Overwriting**: 1-10 configurable passes with cryptographically secure random data
- **Filename Obfuscation**: 3-pass renaming with 48-character random names
- **NTFS Journal Flooding**: Automatic metadata obfuscation without disabling system features
- **VSS Storage Flooding**: Forces deletion of shadow copies through natural Windows mechanisms
- **Automated Validation**: PhotoRec recovery testing to verify secure deletion
- **Free Space Wiping**: Optional integration with Windows cipher command
- **Optimized Performance**: Smart buffering and batched disk operations for 40-60% speed improvement

## Features

### Security Features

- Multi-pass file content overwriting (default: 3 passes)
- Secure file and directory renaming (3 passes, 48-char random names)
- NTFS journal flooding with auto-sizing
- Volume Shadow Copy (VSS) flooding with auto-detection
- Automated validation with PhotoRec recovery testing
- Auto-installation of PhotoRec (TestDisk) via winget
- Progress tracking with ETA (requires tqdm)
- Comprehensive security warnings (VSS, NTFS journal)
- Windows cipher integration for free space wiping

### Performance Optimizations

- Single fsync per file (after all passes) for 40-60% speed improvement
- Smart buffering (8KB) instead of unbuffered I/O
- Chunked processing (1MB chunks) for large files
- Progress bars with throughput statistics

### Safety Features

- Explicit confirmation required (type 'DELETE')
- File and directory counting before deletion
- Detailed risk warnings for VSS and journal operations
- Graceful error handling with permission checks
- Automatic cleanup on errors

## Installation

### Requirements

- Python 3.7 or higher
- Windows (for VSS/journal flooding and cipher features)
- Administrator privileges (recommended for optimal performance)

### Optional Dependencies

For progress bars and better user experience:

```bash
pip install tqdm
```

### Quick Start

```bash
# Clone or download the repository
cd SecureDiskWipe

# Basic usage
python secure-wipe.py /path/to/folder

# Maximum security (recommended)
python secure-wipe.py /path/to/folder --flood-journal --flood-vss
```

## Usage

### Basic Examples

```bash
# Delete folder with default settings (3 passes, renaming enabled)
python secure-wipe.py c:\temp\coding\sensitive-data

# Fast mode (1 pass)
python secure-wipe.py c:\temp\coding\sensitive-data --passes=1

# Skip renaming (faster but less secure)
python secure-wipe.py c:\temp\coding\sensitive-data --no-rename

# Verbose output
python secure-wipe.py c:\temp\coding\sensitive-data --verbose
```

### Advanced Examples

```bash
# Maximum security with auto-sized flooding
python secure-wipe.py c:\temp\coding\sensitive-data --flood-journal --flood-vss

# Maximum security with validation
python secure-wipe.py c:\temp\coding\sensitive-data --flood-journal --flood-vss --validate

# Manual control of flooding
python secure-wipe.py c:\temp\coding\sensitive-data --flood-journal=100000 --flood-vss=20

# Extra paranoid (5 passes + flooding + validation)
python secure-wipe.py c:\temp\coding\sensitive-data --passes=5 --flood-journal --flood-vss --validate
```

## How It Works

### Step 1: File/Folder Renaming (Default)

Each file and folder is renamed 3 times with cryptographically random 48-character names:

```
secret-document.pdf -> a8f3d9e2c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8.tmp
a8f3d9e2c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8.tmp -> b4c7e1f9d8e3c2a1f6e5d4c3b2a1f0e9d8c7b6a5f4e3.tmp
b4c7e1f9d8e3c2a1f6e5d4c3b2a1f0e9d8c7b6a5f4e3.tmp -> c9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9.tmp
```

This obscures filenames in:
- Directory metadata
- NTFS Master File Table (MFT)
- File system journals

### Step 2: Content Overwriting

Each file is overwritten with cryptographically secure random data:

- Default: 3 passes
- Configurable: 1-10 passes
- Uses `os.urandom()` for CSPRNG
- 1MB chunks for efficient processing
- Single fsync after all passes (optimization)

### Step 3: VSS Flooding (Optional)

```bash
--flood-vss
```

Automatically detects VSS storage allocation and writes large files to fill 80% of the maximum storage. This forces Windows to delete the oldest shadow copies using its built-in FIFO mechanism.

**Why this is safer than manual deletion:**
- No system features disabled
- No registry changes
- Natural Windows cleanup mechanism
- Preserves system restore functionality
- Can be run without admin privileges

**Process:**
1. Query VSS storage info: `vssadmin list shadowstorage`
2. Calculate target (80% of max allocation)
3. Create large files (100MB each)
4. Delete files to trigger VSS activity
5. Windows automatically removes oldest snapshots

### Step 4: Journal Flooding (Optional)

```bash
--flood-journal
```

Automatically detects NTFS journal size and creates optimal number of dummy file operations to fill the circular journal buffer by 150%.

**Why this is safer than manual deletion:**
- Journal remains enabled
- Windows Search continues working
- No system performance impact
- Backup tools unaffected
- Metadata pushed out naturally

**Process:**
1. Query journal size: `fsutil usn queryjournal`
2. Calculate operations needed: `(journal_size × 1.5) ÷ (400 bytes × 5 ops)`
3. Create dummy files with random names
4. Rename each file 3 times
5. Delete all dummy files
6. Original filenames buried in noise

### Step 5: Deletion Validation (Optional)

```bash
--validate
```

Automatically tests whether files can be recovered using PhotoRec (a professional open-source file recovery tool).

**What it does:**
- Checks if winget (Windows Package Manager) is installed
- Auto-installs PhotoRec (TestDisk package) via winget if not present
- Runs a file recovery scan on free space
- Checks for original filenames in recovered files
- Reports recoverable files and provides recommendations

**Process:**
1. Install PhotoRec if needed: `winget install CGSecurity.TestDisk`
2. Run PhotoRec scan: `photorec /d recovery_dir /cmd [drive] partition_none,freespace,search`
3. Analyze recovered files for original filenames
4. Count recoverable files
5. Provide success/failure report with recommendations

**Why PhotoRec is better:**
- Professional-grade tool used in forensics
- Excellent command-line support for automation
- Scans free space (where deleted files exist)
- Open-source and actively maintained
- More thorough than consumer recovery tools

**Why this is useful:**
- Verifies secure deletion worked as expected
- Identifies if shadow copies or journal entries survived
- Provides actionable recommendations for improvement
- Automated and hands-off
- Uses the same tools forensic investigators use

**Typical Results:**
- **Success**: No recoverable files, no original filenames found
- **Partial Success**: Files renamed but may be recoverable (recommend cipher /w)
- **Warning**: Original filenames or recoverable files detected (recommend flooding)

### Step 6: Free Space Wiping (Optional)

**IMPORTANT**: `cipher /w` wipes **ALL free space on the ENTIRE DRIVE**, not just the folder you deleted!

When you run `cipher /w:c:\temp`, it:
- Uses `c:\temp` only as a **temp file location**
- But wipes **ALL free space on C: drive** (could be 100-500+ GB)
- Does **3 full passes** (0x00, 0xFF, random data)
- Takes **30 minutes to several hours** depending on free space

**Why you might NOT need it**:
- Your files are already securely deleted (3 overwrites by default)
- cipher /w only helps if you want to wipe OTHER deleted files from weeks/months ago
- Very slow compared to the targeted deletion this tool provides

**When to use it**:
- You want to erase ALL deleted files on the drive
- Maximum paranoia
- Drive about to be disposed of
- Forensic analysis is a real threat

## Security Considerations

### What This Tool Protects Against

- Standard file recovery tools (Recuva, PhotoRec, etc.)
- Undelete utilities
- File carving from unallocated space
- Directory entry analysis
- MFT record examination
- Basic forensic analysis

### What This Tool CANNOT Fully Protect Against

- **Advanced forensic tools**: Government-level forensics may still recover data
- **SSD wear-leveling**: Physical controller may write to different locations
- **Cloud backups**: Files already backed up externally
- **Live system snapshots**: VSS snapshots taken during operation
- **Hardware forensics**: Direct NAND chip analysis
- **Network backups**: Files transmitted to backup servers
- **Email attachments**: Files already sent via email

### Recommendations for Maximum Security

1. **Enable full-disk encryption BEFORE storing sensitive data** (BitLocker, VeraCrypt)
2. **Disable VSS before creating sensitive files** (or use --flood-vss)
3. **Run as Administrator** for optimal VSS/journal access
4. **Use SSD secure erase** for entire drive wiping (manufacturer tools)
5. **Physical destruction** for extremely sensitive data

## Performance

### Benchmarks (117k files, 9.38 GB)

**Basic deletion (3 passes + renaming):**
- Fast NVMe: 35-55 minutes
- Standard SSD: 60-100 minutes
- HDD: 2-3.5 hours

**With flooding (--flood-journal --flood-vss):**
- Fast NVMe: 45-80 minutes
- Standard SSD: 75-120 minutes
- HDD: 3-5 hours

**Fast mode (1 pass + renaming):**
- Fast NVMe: 15-25 minutes
- Standard SSD: 25-40 minutes
- HDD: 50-100 minutes

## Troubleshooting

### Permission Denied Errors

Run as Administrator:
```bash
# Right-click Command Prompt -> Run as Administrator
python secure-wipe.py c:\temp\folder
```

### Progress Bar Not Showing

Install tqdm:
```bash
pip install tqdm
```

### VSS Flooding Not Working

Check if VSS is enabled:
```bash
vssadmin list shadows
vssadmin list shadowstorage
```

### Journal Flooding Not Working

Check if journal is enabled:
```bash
fsutil usn queryjournal C:
```

## Command-Line Options

```
usage: secure-wipe.py [-h] [--passes N] [--no-rename] [--verbose]
                      [--flood-journal [N]] [--flood-vss [GB]]
                      [--validate]
                      folder_path

positional arguments:
  folder_path          Path to the folder to securely delete

options:
  -h, --help           show this help message and exit
  --passes N           Number of overwrite passes (1-10, default: 3)
  --no-rename          Skip renaming files/folders before deletion
  --verbose            Show detailed progress for each file
  --flood-journal [N]  Flood NTFS journal (auto-sizes or specify N files)
  --flood-vss [GB]     Flood VSS storage (auto-sizes or specify GB)
  --validate           Run recovery test after deletion to verify files cannot be recovered
```

## Legal and Ethical Use

This tool is designed for **defensive security purposes only**:

- Protecting intellectual property before device disposal
- Securing sensitive business data
- Personal privacy protection
- Compliance with data destruction policies
- GDPR "right to erasure" compliance

**DO NOT use this tool for:**
- Destroying evidence of illegal activity
- Evading legal discovery processes
- Violating data retention laws
- Concealing malicious activity

Users are responsible for ensuring their use complies with all applicable laws and regulations.

## Contributing

This is a personal security tool. If you have suggestions or improvements, feel free to fork and modify for your own use.

## License

MIT License - Use at your own risk. No warranty provided.

## Disclaimer

This tool provides reasonable protection against casual recovery attempts but is not foolproof. For absolute data destruction, use full-disk encryption combined with physical media destruction.

The authors are not responsible for:
- Data loss from misuse
- Legal consequences of improper use
- Performance on specific systems
- Compatibility issues

Always test on non-critical data first.

## Acknowledgments

- Built with security and privacy in mind
- Implements industry-standard secure deletion techniques
- Inspired by DoD 5220.22-M and similar standards
- Uses Windows native tools for maximum compatibility

## Version History

### v1.0.0 (2025)
- Initial release
- Multi-pass file overwriting (1-10 passes, default 3)
- Filename obfuscation with 3-pass renaming
- Auto-sizing NTFS journal flooding
- Auto-sizing VSS storage flooding
- Automated validation with PhotoRec recovery testing
- Auto-installation of PhotoRec (TestDisk) via winget
- Progress tracking with tqdm
- Comprehensive security warnings
- Optimized performance (40-60% faster)
