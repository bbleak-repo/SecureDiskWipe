# Security Documentation

## Threat Model

SecureDiskWipe is designed to protect against the following threat scenarios:

### Threats Addressed

1. **Casual Recovery Tools**
   - Recuva, PhotoRec, TestDisk
   - Windows built-in recovery
   - Basic undelete utilities
   - Rating: PROTECTED

2. **File System Forensics**
   - MFT (Master File Table) analysis
   - Directory entry examination
   - Deleted file enumeration
   - Rating: SIGNIFICANTLY MITIGATED

3. **Volume Shadow Copies**
   - VSS snapshots containing old file versions
   - System Restore points
   - Previous Versions feature
   - Rating: MITIGATED (with --flood-vss)

4. **NTFS Journal Analysis**
   - USN journal metadata
   - Filename recovery from journal
   - Timestamp analysis
   - Rating: MITIGATED (with --flood-journal)

5. **Free Space Analysis**
   - File carving from unallocated space
   - Slack space recovery
   - Orphaned data blocks
   - Rating: PROTECTED (with cipher /w)

### Threats NOT Fully Addressed

1. **Advanced Forensics**
   - Government-level forensic tools
   - Direct hardware analysis
   - NAND flash chip reading
   - Rating: PARTIAL PROTECTION

2. **SSD-Specific Issues**
   - Wear-leveling remapping
   - Over-provisioning hidden space
   - TRIM command delays
   - Rating: LIMITED PROTECTION

3. **External Copies**
   - Cloud backups
   - Network file shares
   - Email attachments
   - External drives
   - Rating: NOT ADDRESSED

4. **Live System Captures**
   - Memory dumps
   - Hibernation files
   - Page files
   - Crash dumps
   - Rating: NOT ADDRESSED

## Security Techniques

### 1. Multi-Pass Overwriting

**Implementation:**
- Uses `os.urandom()` for cryptographically secure random data (CSPRNG)
- Default 3 passes (configurable 1-10)
- 1MB chunks for efficient memory usage
- Single fsync after all passes (performance optimization)

**Security Level:**
- 1 pass: Defeats casual recovery tools
- 3 passes: Defeats most commercial forensics
- 7+ passes: Meets DOD 5220.22-M standard

**Limitations:**
- SSD wear-leveling may preserve old data blocks
- TRIM command may delay actual erasure
- Over-provisioned space not accessible

### 2. Filename Obfuscation

**Implementation:**
- 3-pass renaming with 48-character random hex names
- Uses `secrets.token_hex()` for cryptographic randomness
- Renames both files and directories
- Bottom-up traversal to maintain path validity

**What it protects:**
- Directory metadata
- MFT file name records
- Journal filename entries
- Filesystem path reconstruction

**Security Level:**
- Makes forensic filename recovery extremely difficult
- Requires full MFT analysis and reconstruction
- Effective against automated tools

**Limitations:**
- Original names may exist in:
  - Volume Shadow Copies (until flooded)
  - NTFS journal (until flooded)
  - Backup files
  - System logs

### 3. NTFS Journal Flooding

**Implementation:**
```
1. Query journal size: fsutil usn queryjournal
2. Calculate: (journal_size * 1.5) / (400 bytes * 5 operations)
3. Create dummy files with random names
4. Rename each 3 times (metadata operations)
5. Delete all files
```

**What it does:**
- Fills circular journal buffer with garbage entries
- Forces oldest entries (containing real filenames) to be overwritten
- Targets 150% fill for guaranteed wrap-around
- Typical: 50k-200k file operations

**Security Analysis:**

**Before flooding:**
```
Journal entries (chronological):
[...old system files...]
[create: secret-document.pdf]       <- SENSITIVE
[modify: secret-document.pdf]
[rename: secret-document.pdf -> a8f3d...]
[rename: a8f3d... -> b4c7e...]
[delete: b4c7e...]
[...recent operations...]
```

**After flooding (150k files * 5 ops = 750k operations):**
```
Journal entries (chronological):
[create: flood_f8a3d9e2...tmp]
[rename: flood_f8a3d9e2...tmp -> a9b8...]
[rename: a9b8... -> c7d6...]
[rename: c7d6... -> e5f4...]
[delete: e5f4...]
[... 749,995 more garbage operations ...]
```

**Security Level:**
- Original filename entries pushed out of journal
- Garbage-to-signal ratio: 750,000:1
- Forensic analysis must search through noise
- Natural journal rotation continues pushing out data

**Limitations:**
- Journal may be analyzed before flooding
- Disk imaging before flooding captures journal
- Journal entries may persist in unallocated space
- Windows logs may still contain references

### 4. VSS Storage Flooding

**Implementation:**
```
1. Query VSS: vssadmin list shadowstorage
2. Calculate: max_storage * 0.80
3. Create large files (100MB each)
4. Write random data
5. Delete files (triggers VSS activity)
6. Windows auto-deletes oldest snapshots (FIFO)
```

**How VSS works:**
- Copy-on-write: Only changed blocks stored
- Storage limit: Typically 10% of drive (configurable)
- Deletion policy: FIFO (oldest snapshots deleted first)
- Triggers: Automatic when storage > threshold

**Security Analysis:**

**Before flooding:**
```
VSS Snapshots:
1. 2025-01-10 10:00 AM - Contains sensitive files
2. 2025-01-15 02:00 PM - Contains sensitive files
3. 2025-01-20 08:30 AM - After deletion (still has metadata)

Storage: 5 GB / 50 GB max
```

**After flooding (40 GB written):**
```
VSS Snapshots:
1. [DELETED by Windows - storage full]
2. [DELETED by Windows - storage full]
3. 2025-01-20 08:30 AM - Partial data
4. 2025-01-20 09:00 AM - Flood files created
5. 2025-01-20 09:15 AM - Flood files deleted

Storage: 42 GB / 50 GB max (80% full)
```

**Security Level:**
- Forces deletion of snapshots containing sensitive data
- Uses Windows' own cleanup mechanism
- No system features disabled
- Preserves functionality

**Limitations:**
- Snapshots created during flood may still exist
- VSS may be queried/copied before flooding
- Differential backups may preserve old data
- Registry settings may reveal snapshot history

## Attack Scenarios

### Scenario 1: Casual User with Recovery Tool

**Threat:** User with Recuva or PhotoRec

**Protection:**
- Single overwrite pass: SUFFICIENT
- File content unrecoverable
- Free space wiping: OPTIONAL

**Recommended settings:**
```bash
python secure-wipe.py /path --passes=1
```

### Scenario 2: Corporate IT Forensics

**Threat:** IT department with forensic software

**Protection:**
- 3-pass overwrite: RECOMMENDED
- Filename obfuscation: REQUIRED
- VSS flooding: RECOMMENDED
- Free space wiping: RECOMMENDED

**Recommended settings:**
```bash
python secure-wipe.py /path --passes=3 --flood-vss
```

### Scenario 3: Law Enforcement

**Threat:** Professional forensic analysis

**Protection:**
- 3+ pass overwrite: REQUIRED
- Filename obfuscation: REQUIRED
- VSS flooding: REQUIRED
- Journal flooding: REQUIRED
- Free space wiping: REQUIRED
- Full disk encryption: HIGHLY RECOMMENDED (preventive)

**Recommended settings:**
```bash
python secure-wipe.py /path --passes=5 --flood-vss --flood-journal
# Then run cipher /w when prompted
```

**Additional recommendations:**
- Use BitLocker BEFORE storing sensitive data
- Disable VSS before creating files
- Use encrypted containers (VeraCrypt)
- Consider physical destruction if extremely sensitive

### Scenario 4: Nation-State Actor

**Threat:** Advanced persistent threat with unlimited resources

**Protection:**
- Software-based deletion: INSUFFICIENT
- Physical destruction: REQUIRED

**Recommended approach:**
- Degaussing (HDDs only)
- Physical shredding/pulverization
- Incineration
- Acid dissolution (extreme cases)

**Why software is insufficient:**
- Advanced hardware forensics
- Electron microscopy
- Direct chip analysis
- Firmware exploitation
- Side-channel attacks

## Best Practices

### Before Storing Sensitive Data

1. **Enable Full-Disk Encryption**
   - BitLocker (Windows Pro/Enterprise)
   - VeraCrypt (open source)
   - Then simply delete encryption key when done

2. **Disable Volume Shadow Copies**
   ```bash
   vssadmin delete shadows /all
   vssadmin resize shadowstorage /for=C: /on=C: /maxsize=UNBOUNDED
   vssadmin resize shadowstorage /for=C: /on=C: /maxsize=1GB
   ```

3. **Use Encrypted Containers**
   - VeraCrypt volumes
   - Delete container file when done
   - No need for secure wiping

### During Secure Deletion

1. **Close All Applications**
   - Prevent file locks
   - Avoid permission errors
   - Ensure complete deletion

2. **Run as Administrator**
   - Access all files
   - Query VSS/journal info
   - Optimal performance

3. **Verify Deletion**
   ```bash
   # After deletion, verify VSS is clear
   vssadmin list shadows

   # Check if folder still exists
   dir c:\path\to\deleted\folder
   ```

### After Secure Deletion

1. **Clear Windows Event Logs** (optional)
   ```powershell
   wevtutil cl System
   wevtutil cl Security
   wevtutil cl Application
   ```

2. **Clear Recycle Bin**
   ```bash
   rd /s /q C:\$Recycle.Bin
   ```

3. **Wipe Free Space**
   ```bash
   cipher /w:C:\
   ```

4. **Clear Page File** (on reboot)
   ```
   Registry: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
   Key: ClearPageFileAtShutdown = 1
   ```

## SSD-Specific Considerations

SSDs present unique challenges for secure deletion:

### Issues

1. **Wear Leveling**
   - Controller may write to different physical location
   - Old data may persist in remapped blocks
   - Not accessible via filesystem

2. **Over-Provisioning**
   - ~7-28% of NAND cells hidden from OS
   - Used for wear leveling and performance
   - May contain old data

3. **TRIM Command**
   - Tells SSD which blocks are free
   - Actual erasure may be delayed
   - Not immediate or guaranteed

4. **Firmware Vulnerabilities**
   - Controller firmware may have bugs
   - Secure Erase command may not work
   - Vendor-specific implementations

### SSD Recommendations

1. **Full-Disk Encryption** (best solution)
   - Encrypt before storing data
   - Delete encryption key when done
   - Renders data cryptographically unrecoverable

2. **Manufacturer Secure Erase**
   - Use vendor tools (Samsung Magician, Intel SSD Toolbox)
   - ATA Secure Erase command
   - Erases all cells including over-provisioned

3. **Software Deletion + Multiple Overwrites**
   - Use 3+ passes
   - Better than single pass on SSDs
   - May not catch remapped blocks

4. **Physical Destruction**
   - For extremely sensitive data
   - Shred or incinerate SSD
   - Only 100% guaranteed method

## Compliance

### GDPR "Right to Erasure"

SecureDiskWipe can help comply with GDPR Article 17:

**Requirements:**
- Personal data must be erased when requested
- Deletion must be verifiable
- Backups must be addressed

**How this tool helps:**
- Multi-pass overwriting ensures unrecoverability
- VSS flooding removes shadow copy data
- Logging can provide deletion audit trail

**Limitations:**
- Does not address cloud backups
- Does not handle database records
- Does not cover email/logs

### DOD 5220.22-M (Historical)

The tool can be configured to meet DOD standard:

**Requirements:**
- 7 passes
- Specific data patterns

**Configuration:**
```bash
python secure-wipe.py /path --passes=7
```

**Note:** DOD 5220.22-M has been superseded by NIST SP 800-88.

### NIST SP 800-88 Rev. 1

Modern standard for media sanitization:

**Clear:** Basic overwrite (1-3 passes)
**Purge:** Secure overwrite (3+ passes)
**Destroy:** Physical destruction

**Compliance:**
- This tool provides Clear and Purge levels
- HDDs: 1-3 passes sufficient
- SSDs: Cryptographic erasure preferred (full-disk encryption + key deletion)

## Audit and Logging

The tool currently provides real-time output but does not create audit logs.

**To create audit trail:**

```bash
# Windows
python secure-wipe.py c:\sensitive-folder > deletion-log.txt 2>&1

# Add timestamp
python secure-wipe.py c:\sensitive-folder > deletion-log-%date:~-4,4%%date:~-10,2%%date:~-7,2%.txt 2>&1
```

**Log should contain:**
- Timestamp of operation
- Files/folders deleted
- Number of passes used
- Flooding operations performed
- Any errors encountered

**Security consideration:**
- Deletion logs may reveal what was deleted
- Store logs securely or delete after verification
- Consider encrypted log storage

## Incident Response

If you discover files were not securely deleted:

1. **DO NOT create new files on the drive**
   - Prevents overwriting of deleted data
   - Preserves ability to re-delete

2. **Re-run secure deletion immediately**
   ```bash
   # If files still exist
   python secure-wipe.py /path --passes=5 --flood-vss --flood-journal

   # If already deleted, wipe free space
   cipher /w:C:\
   ```

3. **Check for shadow copies**
   ```bash
   vssadmin list shadows
   vssadmin delete shadows /all
   ```

4. **Check backups**
   - Cloud storage (OneDrive, Google Drive, etc.)
   - Network shares
   - External drives
   - Email attachments

5. **Consider full disk encryption**
   - BitLocker for future sensitive data
   - Encrypt entire drive
   - Protects against incomplete deletion

## Security Updates

This tool implements current best practices as of 2025.

**Monitor for:**
- New forensic techniques
- SSD firmware vulnerabilities
- Windows update changes to VSS/journal
- New recovery tools

**Stay informed:**
- Security research papers
- Forensic tool updates
- Windows security bulletins
- NIST guidelines updates

## Reporting Security Issues

If you discover a security vulnerability in this tool:

1. Do NOT publicly disclose
2. Document the issue with reproduction steps
3. Consider if it's a tool bug or inherent limitation
4. Test on non-sensitive data first

## Conclusion

SecureDiskWipe provides strong protection against most recovery scenarios but is not a silver bullet. For maximum security, use full-disk encryption BEFORE storing sensitive data, then simply delete the encryption key when done.

Remember: **Prevention (encryption) is better than cure (secure deletion).**
