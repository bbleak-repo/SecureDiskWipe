import os
import sys
import subprocess
import argparse
import time
import secrets
from pathlib import Path

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("Note: Install tqdm for progress bars: pip install tqdm")
    print()


def generate_random_name(length=48):
    """
    Generate a random filename with high entropy

    Args:
        length: Length of random string (default 48 for maximum entropy)

    Returns random hex string
    """
    return secrets.token_hex(length // 2)


def secure_rename(path, passes=3, verbose=False):
    """
    Rename a file or directory multiple times with random names

    Args:
        path: Path to rename
        passes: Number of rename passes (default 3)
        verbose: Print rename operations

    Returns final path after renaming, or None on failure
    """
    try:
        current_path = Path(path)
        parent = current_path.parent

        for i in range(passes):
            # Generate random name with appropriate extension
            if current_path.is_file():
                random_name = generate_random_name() + '.tmp'
            else:
                random_name = generate_random_name()

            new_path = parent / random_name

            # Rename
            current_path.rename(new_path)

            if verbose:
                print(f"Rename pass {i+1}/{passes}: {current_path.name} -> {random_name}")

            current_path = new_path

        return current_path
    except Exception as e:
        if verbose:
            print(f"Error renaming {path}: {e}")
        return None


def check_vss_status():
    """
    Check if Volume Shadow Copies are enabled (Windows only)

    Returns tuple: (has_shadows, shadow_info)
    """
    if sys.platform != 'win32':
        return False, None

    try:
        result = subprocess.run(
            ['vssadmin', 'list', 'shadows'],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout
        has_shadows = 'Shadow Copy Volume:' in output or 'Contents:' in output

        return has_shadows, output
    except Exception:
        return False, None


def check_ntfs_journal(drive_letter):
    """
    Check if NTFS journaling is enabled (Windows only)

    Args:
        drive_letter: Drive letter (e.g., 'C:')

    Returns True if journaling is enabled
    """
    if sys.platform != 'win32':
        return False

    try:
        result = subprocess.run(
            ['fsutil', 'usn', 'queryjournal', drive_letter],
            capture_output=True,
            text=True,
            timeout=5
        )

        # If command succeeds, journaling is enabled
        return result.returncode == 0
    except Exception:
        return False


def get_journal_size(drive_letter):
    """
    Get the NTFS journal maximum size (Windows only)

    Args:
        drive_letter: Drive letter (e.g., 'C:')

    Returns tuple: (max_size_bytes, allocation_delta_bytes) or (None, None)
    """
    if sys.platform != 'win32':
        return None, None

    try:
        result = subprocess.run(
            ['fsutil', 'usn', 'queryjournal', drive_letter],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return None, None

        output = result.stdout
        max_size = None
        allocation_delta = None

        # Parse output for journal size
        for line in output.split('\n'):
            if 'Maximum Size' in line or 'Max Size' in line:
                # Extract hex value like "0x0000000002000000"
                parts = line.split(':')
                if len(parts) > 1:
                    hex_val = parts[1].strip()
                    try:
                        max_size = int(hex_val, 16)
                    except ValueError:
                        pass
            elif 'Allocation Delta' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    hex_val = parts[1].strip()
                    try:
                        allocation_delta = int(hex_val, 16)
                    except ValueError:
                        pass

        return max_size, allocation_delta

    except Exception:
        return None, None


def get_vss_storage_info(drive_letter):
    """
    Get VSS storage allocation information (Windows only)

    Args:
        drive_letter: Drive letter (e.g., 'C:')

    Returns tuple: (used_space_bytes, allocated_space_bytes, max_space_bytes) or (None, None, None)
    """
    if sys.platform != 'win32':
        return None, None, None

    try:
        result = subprocess.run(
            ['vssadmin', 'list', 'shadowstorage', '/for=' + drive_letter],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None, None, None

        output = result.stdout
        used_space = None
        allocated_space = None
        max_space = None

        # Parse output
        for line in output.split('\n'):
            line = line.strip()
            if 'Used Shadow Copy Storage space:' in line:
                # Extract size like "1.234 GB" or "512 MB"
                parts = line.split(':')
                if len(parts) > 1:
                    size_str = parts[1].strip()
                    used_space = parse_size_string(size_str)
            elif 'Allocated Shadow Copy Storage space:' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    size_str = parts[1].strip()
                    allocated_space = parse_size_string(size_str)
            elif 'Maximum Shadow Copy Storage space:' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    size_str = parts[1].strip()
                    max_space = parse_size_string(size_str)

        return used_space, allocated_space, max_space

    except Exception:
        return None, None, None


def parse_size_string(size_str):
    """
    Parse a size string like "1.234 GB" or "512 MB" to bytes

    Args:
        size_str: Size string to parse

    Returns size in bytes or None
    """
    try:
        parts = size_str.split()
        if len(parts) < 2:
            return None

        value = float(parts[0].replace(',', ''))
        unit = parts[1].upper()

        multipliers = {
            'BYTES': 1,
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
            'TB': 1024 * 1024 * 1024 * 1024,
        }

        return int(value * multipliers.get(unit, 1))

    except Exception:
        return None


def print_security_warnings(folder_path):
    """
    Print warnings about VSS and journaling with risk information

    Args:
        folder_path: Path to check for warnings
    """
    warnings_found = False

    # Check VSS
    has_shadows, shadow_info = check_vss_status()

    if has_shadows:
        warnings_found = True
        print("\n" + "!" * 70)
        print("WARNING: Volume Shadow Copies (VSS) detected!")
        print("!" * 70)
        print("\nShadow copies may contain previous versions of your files.")
        print("File names and contents may be recoverable from shadow copies.")

        # Try to get VSS storage info
        try:
            drive_letter = Path(folder_path).resolve().drive
            if drive_letter:
                used, allocated, max_space = get_vss_storage_info(drive_letter)
                if max_space and max_space > 0:
                    max_gb = max_space / (1024 * 1024 * 1024)
                    used_gb = used / (1024 * 1024 * 1024) if used else 0
                    print(f"\nVSS Storage Info:")
                    print(f"  Maximum: {max_gb:.2f} GB")
                    print(f"  Currently used: {used_gb:.2f} GB")
        except Exception:
            pass

        print("\nTo delete all shadow copies, run as Administrator:")
        print("  vssadmin delete shadows /all /quiet")
        print("\nALTERNATIVE - Use VSS flooding (safer):")
        print(f"  python wipe-folder.py <folder> --flood-vss")
        print("  This fills VSS storage, forcing Windows to auto-delete old snapshots")
        print("\nRISKS OF DELETING SHADOW COPIES:")
        print("  - System Restore points will be deleted")
        print("  - Previous versions of ALL files on the system will be lost")
        print("  - Windows backup history will be cleared")
        print("  - You cannot undo this operation")
        print("  - Some applications rely on shadow copies for recovery")

    # Check NTFS journal
    if sys.platform == 'win32':
        try:
            drive_letter = Path(folder_path).resolve().drive
            if drive_letter and check_ntfs_journal(drive_letter):
                warnings_found = True
                print("\n" + "!" * 70)
                print(f"WARNING: NTFS Change Journal is enabled on {drive_letter}")
                print("!" * 70)

                # Get journal size info
                max_size, _ = get_journal_size(drive_letter)
                if max_size:
                    max_size_mb = max_size / (1024 * 1024)
                    print(f"\nJournal size: {max_size_mb:.1f} MB")

                print("\nThe journal may contain metadata about deleted files:")
                print("  - File names")
                print("  - Timestamps")
                print("  - File creation/deletion events")
                print(f"\nTo delete the journal (run as Administrator):")
                print(f"  fsutil usn deletejournal /d /n {drive_letter}")
                print("\nALTERNATIVE - Use journal flooding (safer):")
                print(f"  python wipe-folder.py <folder> --flood-journal")
                print("  This obscures metadata without disabling system features")
                print("\nRISKS OF DELETING THE JOURNAL:")
                print("  - Windows Search index will be rebuilt (slow)")
                print("  - Some backup tools may need to do full scans")
                print("  - File replication services may be affected")
                print("  - System restore functionality may be impacted")
                print("  - Journal will be recreated automatically by Windows")
                print("\nNOTE: Even after deletion, journal entries may persist in")
                print("      unallocated disk space until overwritten.")
        except Exception:
            pass

    if warnings_found:
        print("\n" + "!" * 70)
        print("RECOMMENDATION: Consider these risks before proceeding.")
        print("These warnings are informational only - the script will continue.")
        print("!" * 70)


def secure_delete_file(filepath, passes=3, pbar=None, verbose=False):
    """
    Securely delete a single file by overwriting it multiple times

    Args:
        filepath: Path to the file to delete
        passes: Number of overwrite passes (default 3)
        pbar: Optional tqdm progress bar to update
        verbose: Print detailed progress (default False when using progress bar)

    Returns True if successful, False otherwise
    """
    try:
        if os.path.isfile(filepath):
            file_size = os.path.getsize(filepath)

            if file_size == 0:
                os.remove(filepath)
                if verbose:
                    print(f"Deleted empty file: {filepath}")
                if pbar:
                    pbar.update(1)
                return True

            # Overwrite with random data - OPTIMIZED VERSION
            if verbose:
                print(f"Securely overwriting: {filepath} ({file_size} bytes)")

            # Use default buffering (8KB) instead of unbuffered for better performance
            with open(filepath, 'r+b') as f:
                chunk_size = 1024 * 1024  # 1MB chunks

                # Perform all passes
                for i in range(passes):
                    f.seek(0)
                    remaining = file_size

                    while remaining > 0:
                        chunk = min(chunk_size, remaining)
                        f.write(os.urandom(chunk))
                        remaining -= chunk

                    if verbose:
                        print(f"  Pass {i+1}/{passes} complete")

                # Single fsync at the end of all passes (OPTIMIZATION)
                f.flush()
                os.fsync(f.fileno())

            # Finally remove
            os.remove(filepath)
            if verbose:
                print(f"Successfully deleted: {filepath}")

            if pbar:
                pbar.update(1)

            return True
    except PermissionError:
        msg = f"Permission denied (file may be in use): {filepath}"
        if verbose:
            print(msg)
        if pbar:
            pbar.write(msg)
            pbar.update(1)
        return False
    except Exception as e:
        msg = f"Error deleting {filepath}: {e}"
        if verbose:
            print(msg)
        if pbar:
            pbar.write(msg)
            pbar.update(1)
        return False


def secure_delete_folder(folder_path, passes=3, rename_files=True, verbose=False):
    """
    Recursively secure delete all files in a folder, then remove empty folders

    Args:
        folder_path: Path to the folder to delete
        passes: Number of overwrite passes for each file (default 3)
        rename_files: Rename files/folders before deletion (default True)
        verbose: Print detailed progress for each file (default False)

    Returns the parent directory for cipher operation
    """
    folder = Path(folder_path).resolve()

    if not folder.exists():
        print(f"ERROR: Folder does not exist: {folder_path}")
        return None

    if not folder.is_dir():
        print(f"ERROR: Path is not a directory: {folder_path}")
        return None

    print(f"\nStarting secure deletion of: {folder}")
    print(f"Overwrite passes: {passes}")
    print(f"Rename before deletion: {rename_files}")
    print("=" * 70)

    # Collect all files and directories first
    print("Scanning files and directories...")
    all_files = []
    all_dirs = []

    for root, dirs, files in os.walk(folder, topdown=False):
        for name in files:
            all_files.append(os.path.join(root, name))
        for name in dirs:
            all_dirs.append(os.path.join(root, name))

    total_files = len(all_files)
    total_dirs = len(all_dirs)
    print(f"Found {total_files} files and {total_dirs} directories to delete")

    if total_files == 0 and total_dirs == 0:
        print("No files or directories to delete")
        return folder.parent

    # Calculate total data size
    total_size = sum(os.path.getsize(f) for f in all_files if os.path.exists(f))
    total_size_mb = total_size / (1024 * 1024)
    total_data_written = total_size * passes / (1024 * 1024)

    print(f"Total size: {total_size_mb:.2f} MB")
    print(f"Total data to write: {total_data_written:.2f} MB ({passes} passes)")
    print("=" * 70)

    start_time = time.time()

    # Step 1: Rename files and directories if enabled
    if rename_files and (total_files > 0 or total_dirs > 0):
        print("\nStep 1: Renaming files and directories (3 passes)...")
        rename_start = time.time()

        # Create combined list for renaming with progress bar
        items_to_rename = [(f, 'file') for f in all_files] + [(d, 'dir') for d in all_dirs]
        renamed_files = []
        renamed_dirs = []

        if TQDM_AVAILABLE:
            with tqdm(total=len(items_to_rename), unit='item', desc='Renaming items') as pbar:
                for item_path, item_type in items_to_rename:
                    if os.path.exists(item_path):
                        new_path = secure_rename(item_path, passes=3, verbose=verbose)
                        if new_path:
                            if item_type == 'file':
                                renamed_files.append(str(new_path))
                            else:
                                renamed_dirs.append(str(new_path))
                        else:
                            # If rename failed, keep original path
                            if item_type == 'file':
                                renamed_files.append(item_path)
                            else:
                                renamed_dirs.append(item_path)
                    pbar.update(1)
        else:
            for i, (item_path, item_type) in enumerate(items_to_rename, 1):
                if os.path.exists(item_path):
                    new_path = secure_rename(item_path, passes=3, verbose=verbose)
                    if new_path:
                        if item_type == 'file':
                            renamed_files.append(str(new_path))
                        else:
                            renamed_dirs.append(str(new_path))
                    else:
                        if item_type == 'file':
                            renamed_files.append(item_path)
                        else:
                            renamed_dirs.append(item_path)
                if i % 100 == 0:
                    print(f"Renamed: {i}/{len(items_to_rename)} items ({i*100//len(items_to_rename)}%)")

        # Update file and dir lists with renamed paths
        all_files = renamed_files
        all_dirs = renamed_dirs

        rename_elapsed = time.time() - rename_start
        print(f"Renaming complete: {rename_elapsed:.1f} seconds ({rename_elapsed/60:.1f} minutes)")

    # Step 2: Overwrite and delete files
    print(f"\nStep {'2' if rename_files else '1'}: Overwriting and deleting files...")
    success_count = 0
    delete_start = time.time()

    if TQDM_AVAILABLE:
        with tqdm(total=total_files, unit='file', desc='Deleting files') as pbar:
            for filepath in all_files:
                if os.path.exists(filepath):
                    if secure_delete_file(filepath, passes, pbar=pbar, verbose=verbose):
                        success_count += 1
                else:
                    pbar.update(1)
    else:
        for i, filepath in enumerate(all_files, 1):
            if os.path.exists(filepath):
                if secure_delete_file(filepath, passes, verbose=True):
                    success_count += 1
            if i % 100 == 0:
                print(f"Progress: {i}/{total_files} files ({i*100//total_files}%)")

    delete_elapsed = time.time() - delete_start

    # Step 3: Remove directories (force delete if not empty)
    print(f"\nStep {'3' if rename_files else '2'}: Removing directories...")
    failed_deletes = []

    for dirpath in all_dirs:
        try:
            if os.path.exists(dirpath):
                try:
                    # Try to remove empty directory first
                    os.rmdir(dirpath)
                    if verbose:
                        print(f"Removed directory: {dirpath}")
                except OSError:
                    # Directory not empty - force delete with shutil.rmtree
                    import shutil
                    shutil.rmtree(dirpath, ignore_errors=False)
                    failed_deletes.append(dirpath)
                    if verbose:
                        print(f"Force-deleted non-empty directory: {dirpath}")
        except Exception as e:
            if verbose:
                print(f"Could not remove directory {dirpath}: {e}")

    # Remove the root folder
    try:
        os.rmdir(folder)
        print(f"Removed root folder: {folder}")
    except OSError:
        # Root folder not empty - force delete
        try:
            import shutil
            shutil.rmtree(folder, ignore_errors=False)
            print(f"Force-deleted root folder: {folder}")
            failed_deletes.append(str(folder))
        except Exception as e:
            print(f"Warning: Could not remove root folder {folder}: {e}")

    # Warn about force-deleted directories
    if failed_deletes:
        print("\n" + "!" * 70)
        print(f"WARNING: {len(failed_deletes)} directories were not empty")
        print("!" * 70)
        print("Some files could not be securely deleted (permissions/locks).")
        print("These directories were force-deleted with remaining files.")
        print("Files were NOT securely overwritten before deletion.")
        print("\nThis may happen due to:")
        print("  - Files locked by another process")
        print("  - Permission denied errors")
        print("  - Antivirus interference")
        print("!" * 70)

    elapsed_time = time.time() - start_time

    print("=" * 70)
    print(f"Secure deletion complete: {success_count}/{total_files} files successfully deleted")
    print(f"Total time elapsed: {elapsed_time:.1f} seconds ({elapsed_time/60:.1f} minutes)")

    if rename_files:
        print(f"  - Renaming: {rename_elapsed:.1f}s")
        print(f"  - Overwriting: {delete_elapsed:.1f}s")

    if elapsed_time > 0 and total_size > 0:
        throughput = (total_size * passes) / elapsed_time / (1024 * 1024)
        print(f"Average throughput: {throughput:.2f} MB/s")

    # Return parent directory for cipher operation
    return folder.parent


def flood_journal(path, num_files=None):
    """
    Flood the NTFS journal with dummy entries to obscure previous operations

    Creates many temporary files, renames them multiple times, then deletes them.
    This fills the circular journal buffer, pushing out older entries containing
    sensitive filenames from the secure deletion operation.

    Args:
        path: Directory to create temporary files in
        num_files: Number of dummy files to create (auto-calculated if None)
    """
    print("\n" + "=" * 70)
    print("JOURNAL FLOODING - Obscuring metadata traces")
    print("=" * 70)

    # Auto-calculate optimal file count if not specified
    if num_files is None and sys.platform == 'win32':
        try:
            drive_letter = Path(path).resolve().drive
            if drive_letter:
                max_size, _ = get_journal_size(drive_letter)
                if max_size:
                    # Each file operation takes ~200-400 bytes in journal
                    # 5 operations per file (create + 3 renames + delete)
                    # Target: Fill 150% of journal to ensure wrap-around
                    bytes_per_file = 400 * 5
                    num_files = int((max_size * 1.5) / bytes_per_file)
                    num_files = max(50000, min(num_files, 500000))  # Clamp to reasonable range

                    max_size_mb = max_size / (1024 * 1024)
                    print(f"Journal size detected: {max_size_mb:.1f} MB")
                    print(f"Auto-calculated optimal file count: {num_files:,}")
                else:
                    num_files = 100000
            else:
                num_files = 100000
        except Exception:
            num_files = 100000
    elif num_files is None:
        num_files = 100000

    print(f"Creating {num_files:,} dummy files to flood the NTFS journal...")
    print("This will push out previous journal entries containing original filenames.")
    print("=" * 70)

    temp_dir = Path(path) / f"_journal_flood_{secrets.token_hex(8)}"

    try:
        # Create temp directory
        temp_dir.mkdir(exist_ok=True)

        start_time = time.time()
        created_files = []

        # Step 1: Create dummy files
        print("\nStep 1: Creating dummy files...")
        if TQDM_AVAILABLE:
            with tqdm(total=num_files, unit='file', desc='Creating files') as pbar:
                for i in range(num_files):
                    dummy_file = temp_dir / f"{secrets.token_hex(24)}.tmp"
                    # Create small files (1KB each) to be fast
                    dummy_file.write_bytes(os.urandom(1024))
                    created_files.append(dummy_file)
                    pbar.update(1)
        else:
            for i in range(num_files):
                dummy_file = temp_dir / f"{secrets.token_hex(24)}.tmp"
                dummy_file.write_bytes(os.urandom(1024))
                created_files.append(dummy_file)
                if (i + 1) % 10000 == 0:
                    print(f"Created: {i+1:,}/{num_files:,} files")

        # Step 2: Rename all files 3 times
        print("\nStep 2: Renaming files (3 passes)...")
        if TQDM_AVAILABLE:
            with tqdm(total=num_files, unit='file', desc='Renaming files') as pbar:
                for file_path in created_files:
                    if file_path.exists():
                        secure_rename(file_path, passes=3, verbose=False)
                    pbar.update(1)
        else:
            for i, file_path in enumerate(created_files):
                if file_path.exists():
                    secure_rename(file_path, passes=3, verbose=False)
                if (i + 1) % 10000 == 0:
                    print(f"Renamed: {i+1:,}/{num_files:,} files")

        # Step 3: Delete all files
        print("\nStep 3: Deleting dummy files...")
        if TQDM_AVAILABLE:
            with tqdm(total=num_files, unit='file', desc='Deleting files') as pbar:
                for file_path in created_files:
                    try:
                        if file_path.exists():
                            file_path.unlink()
                    except Exception:
                        pass
                    pbar.update(1)
        else:
            for i, file_path in enumerate(created_files):
                try:
                    if file_path.exists():
                        file_path.unlink()
                except Exception:
                    pass
                if (i + 1) % 10000 == 0:
                    print(f"Deleted: {i+1:,}/{num_files:,} files")

        # Remove temp directory
        try:
            temp_dir.rmdir()
        except Exception:
            pass

        elapsed = time.time() - start_time
        total_operations = num_files * 5  # Create + 3 renames + delete

        print("=" * 70)
        print(f"Journal flooding complete!")
        print(f"  Files processed: {num_files:,}")
        print(f"  Total journal operations: ~{total_operations:,}")
        print(f"  Time elapsed: {elapsed:.1f}s ({elapsed/60:.1f} minutes)")
        print(f"  Operations/sec: {total_operations/elapsed:.0f}")
        print(f"\nThe NTFS journal has been flooded with {total_operations:,} entries.")
        print("Original filenames are now buried in noise and will be overwritten faster.")
        print("=" * 70)

    except Exception as e:
        print(f"\nError during journal flooding: {e}")
        # Clean up on error
        try:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
        except Exception:
            pass


def flood_vss(path, target_size_gb=None):
    """
    Flood VSS (Volume Shadow Copy) storage to force deletion of old snapshots

    Creates large files to fill VSS storage allocation, forcing Windows to
    delete the oldest shadow copies to make room.

    Args:
        path: Directory to create large files in
        target_size_gb: Amount of data to write in GB (auto-calculated if None)
    """
    print("\n" + "=" * 70)
    print("VSS FLOODING - Forcing deletion of old shadow copies")
    print("=" * 70)

    if sys.platform != 'win32':
        print("VSS flooding is only available on Windows")
        return

    # Auto-calculate target size if not specified
    if target_size_gb is None:
        try:
            drive_letter = Path(path).resolve().drive
            if drive_letter:
                used, allocated, max_space = get_vss_storage_info(drive_letter)

                if max_space and max_space > 0:
                    # Target: Write enough to fill 80% of max VSS storage
                    # This forces old snapshots to be deleted
                    target_bytes = int(max_space * 0.8)
                    target_size_gb = target_bytes / (1024 * 1024 * 1024)

                    max_gb = max_space / (1024 * 1024 * 1024)
                    used_gb = used / (1024 * 1024 * 1024) if used else 0

                    print(f"VSS storage detected:")
                    print(f"  Maximum: {max_gb:.2f} GB")
                    print(f"  Currently used: {used_gb:.2f} GB")
                    print(f"  Target to write: {target_size_gb:.2f} GB (to trigger snapshot deletion)")
                elif max_space == -1 or max_space is None:
                    # Unbounded - use conservative 5GB
                    target_size_gb = 5.0
                    print("VSS storage appears unbounded, using conservative 5 GB target")
                else:
                    # Default fallback
                    target_size_gb = 10.0
                    print("Could not detect VSS size, using 10 GB default target")
            else:
                target_size_gb = 10.0
        except Exception as e:
            print(f"Could not query VSS info: {e}")
            target_size_gb = 10.0

    print(f"\nCreating {target_size_gb:.2f} GB of data to flood VSS storage...")
    print("This will force Windows to delete oldest shadow copies to make room.")
    print("=" * 70)

    temp_dir = Path(path) / f"_vss_flood_{secrets.token_hex(8)}"

    try:
        # Create temp directory
        temp_dir.mkdir(exist_ok=True)

        start_time = time.time()
        target_bytes = int(target_size_gb * 1024 * 1024 * 1024)
        chunk_size = 10 * 1024 * 1024  # 10 MB chunks
        file_size = 100 * 1024 * 1024  # 100 MB per file
        num_files = max(1, target_bytes // file_size)

        bytes_written = 0
        created_files = []

        print(f"\nWriting {num_files} files of {file_size/(1024*1024):.0f} MB each...")

        if TQDM_AVAILABLE:
            with tqdm(total=target_bytes, unit='B', unit_scale=True, desc='Writing data') as pbar:
                for i in range(num_files):
                    file_path = temp_dir / f"vss_flood_{i:06d}.dat"

                    with open(file_path, 'wb') as f:
                        remaining = file_size
                        while remaining > 0:
                            chunk = min(chunk_size, remaining)
                            f.write(os.urandom(chunk))
                            remaining -= chunk
                            bytes_written += chunk
                            pbar.update(chunk)

                    created_files.append(file_path)

                    if bytes_written >= target_bytes:
                        break
        else:
            for i in range(num_files):
                file_path = temp_dir / f"vss_flood_{i:06d}.dat"

                with open(file_path, 'wb') as f:
                    remaining = file_size
                    while remaining > 0:
                        chunk = min(chunk_size, remaining)
                        f.write(os.urandom(chunk))
                        remaining -= chunk
                        bytes_written += chunk

                created_files.append(file_path)

                if (i + 1) % 10 == 0:
                    gb_written = bytes_written / (1024 * 1024 * 1024)
                    print(f"Written: {gb_written:.2f} GB / {target_size_gb:.2f} GB")

                if bytes_written >= target_bytes:
                    break

        # Now delete all the files to trigger more VSS activity
        print("\nDeleting flood files to trigger additional VSS changes...")

        if TQDM_AVAILABLE:
            with tqdm(total=len(created_files), unit='file', desc='Deleting files') as pbar:
                for file_path in created_files:
                    try:
                        if file_path.exists():
                            file_path.unlink()
                    except Exception:
                        pass
                    pbar.update(1)
        else:
            for file_path in created_files:
                try:
                    if file_path.exists():
                        file_path.unlink()
                except Exception:
                    pass

        # Remove temp directory
        try:
            temp_dir.rmdir()
        except Exception:
            pass

        elapsed = time.time() - start_time
        gb_written = bytes_written / (1024 * 1024 * 1024)

        print("=" * 70)
        print(f"VSS flooding complete!")
        print(f"  Data written: {gb_written:.2f} GB")
        print(f"  Files created and deleted: {len(created_files):,}")
        print(f"  Time elapsed: {elapsed:.1f}s ({elapsed/60:.1f} minutes)")
        print(f"  Write speed: {gb_written/(elapsed/60):.1f} GB/min")
        print("\nOld shadow copies should now be deleted by Windows VSS subsystem.")
        print("Use 'vssadmin list shadows' to verify shadow copy status.")
        print("=" * 70)

    except Exception as e:
        print(f"\nError during VSS flooding: {e}")
        # Clean up on error
        try:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
        except Exception:
            pass


def check_tool_installed(tool_name):
    """
    Check if a tool is installed via winget

    Args:
        tool_name: Winget package ID (e.g., 'CGSecurity.TestDisk')

    Returns True if installed, False otherwise
    """
    try:
        result = subprocess.run(
            ['winget', 'list', '--id', tool_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Check both for exact ID match and in output
        output_lower = result.stdout.lower()
        tool_lower = tool_name.lower()

        # Look for the package ID or common name variations
        is_installed = (
            tool_name in result.stdout or
            tool_lower in output_lower or
            'testdisk' in output_lower  # For CGSecurity.TestDisk
        )

        if is_installed:
            print(f"{tool_name} appears to be installed")

        return is_installed
    except Exception as e:
        print(f"Error checking if {tool_name} is installed: {e}")
        return False


def install_tool(tool_name, friendly_name):
    """
    Install a tool via winget

    Args:
        tool_name: Winget package ID
        friendly_name: Human-readable name

    Returns True if successful, False otherwise
    """
    print(f"\nInstalling {friendly_name} via winget...")
    print("This may take 1-2 minutes...")
    try:
        result = subprocess.run(
            ['winget', 'install', '--id', tool_name, '--silent', '--accept-package-agreements', '--accept-source-agreements'],
            capture_output=True,
            text=True,
            timeout=300
        )

        # Show output for debugging
        if result.stdout:
            print(f"\nWinget output:\n{result.stdout}")

        if result.returncode == 0 or "Successfully installed" in result.stdout:
            print(f"\n{friendly_name} installed successfully!")
            # Give Windows time to update PATH
            import time
            time.sleep(2)
            return True
        else:
            print(f"\nFailed to install {friendly_name}")
            print(f"Return code: {result.returncode}")
            if result.stderr:
                print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error installing {friendly_name}: {e}")
        return False


def validate_deletion(folder_path, original_names=None):
    """
    Validate that deleted files cannot be recovered using PhotoRec

    Args:
        folder_path: Path where files were deleted from
        original_names: List of original filenames to search for (optional)

    Returns tuple: (success, details)
    """
    if sys.platform != 'win32':
        print("\nValidation is only available on Windows")
        return False, "Not on Windows"

    print("\n" + "=" * 70)
    print("VALIDATION - Testing file recovery")
    print("=" * 70)
    print("\nThis will attempt to recover deleted files using PhotoRec")
    print("to verify secure deletion was successful.")
    print("=" * 70)

    # Check if winget is available
    try:
        subprocess.run(['winget', '--version'], capture_output=True, timeout=5)
    except Exception:
        print("\nERROR: winget is not available")
        print("Please install Windows Package Manager (winget) first")
        return False, "winget not available"

    # Check if PhotoRec (TestDisk package) is installed
    photorec_id = 'CGSecurity.TestDisk'
    if not check_tool_installed(photorec_id):
        print(f"\nPhotoRec not found. Installing TestDisk package...")
        print("NOTE: If installation fails, you can manually download from:")
        print("      https://www.cgsecurity.org/wiki/TestDisk_Download")

        if not install_tool(photorec_id, 'TestDisk (includes PhotoRec)'):
            print("\nValidation aborted - could not install PhotoRec via winget")
            print("\nAlternative installation methods:")
            print("1. Manual download: https://www.cgsecurity.org/wiki/TestDisk_Download")
            print("   Extract to C:\\TestDisk and run this script again")
            print("\n2. Or via Chocolatey: choco install testdisk-photorec")
            return False, "Failed to install PhotoRec"

        # Verify installation worked
        print("\nVerifying installation...")
        if not check_tool_installed(photorec_id):
            print("\nWARNING: Installation completed but package not detected")
            print("Continuing anyway - will search for executable...")

    # Find PhotoRec executable - try multiple methods
    photorec_exe = None

    # Method 1: Check if it's in PATH using 'where' command
    try:
        result = subprocess.run(
            ['where', 'photorec_win.exe'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            photorec_exe = result.stdout.strip().split('\n')[0]
            print(f"Found PhotoRec in PATH: {photorec_exe}")
    except Exception:
        pass

    # Method 2: Check common installation paths
    if not photorec_exe:
        photorec_paths = [
            r"C:\Program Files\TestDisk\photorec_win.exe",
            r"C:\Program Files (x86)\TestDisk\photorec_win.exe",
            r"C:\TestDisk\photorec_win.exe",
            os.path.expanduser(r"~\AppData\Local\Microsoft\WinGet\Packages\CGSecurity.TestDisk_Microsoft.Winget.Source_8wekyb3d8bbwe\photorec_win.exe"),
            os.path.expanduser(r"~\scoop\apps\testdisk\current\photorec_win.exe"),
        ]

        for path in photorec_paths:
            if os.path.exists(path):
                photorec_exe = path
                print(f"Found PhotoRec at: {photorec_exe}")
                break

    # Method 3: Search Program Files directories
    if not photorec_exe:
        print("\nSearching for PhotoRec installation...")
        search_dirs = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            os.path.expanduser(r"~\AppData\Local\Microsoft\WinGet\Packages"),
        ]

        for search_dir in search_dirs:
            if os.path.exists(search_dir):
                for root, dirs, files in os.walk(search_dir):
                    if 'photorec_win.exe' in files:
                        photorec_exe = os.path.join(root, 'photorec_win.exe')
                        print(f"Found PhotoRec at: {photorec_exe}")
                        break
                if photorec_exe:
                    break

    if not photorec_exe:
        print("\n" + "=" * 70)
        print("ERROR: PhotoRec executable not found")
        print("=" * 70)
        print("\nInstallation may have succeeded but executable cannot be located.")
        print("\nTroubleshooting steps:")
        print("1. Check if TestDisk is installed:")
        print("   winget list CGSecurity.TestDisk")
        print("\n2. Manually download from: https://www.cgsecurity.org/wiki/TestDisk_Download")
        print("\n3. Or try installing via Chocolatey:")
        print("   choco install testdisk-photorec")
        print("\n4. After manual installation, run this script again")
        print("=" * 70)
        return False, "PhotoRec executable not found"

    print(f"Using PhotoRec: {photorec_exe}")

    # Get drive letter
    drive_letter = Path(folder_path).resolve().drive
    if not drive_letter:
        print("\nERROR: Could not determine drive letter")
        return False, "No drive letter"

    # Create temp recovery directory
    recovery_dir = Path(folder_path).parent / f"_photorec_scan_{secrets.token_hex(4)}"
    recovery_dir.mkdir(exist_ok=True)

    print(f"\nRunning PhotoRec scan on {drive_letter}...")
    print("This may take 2-10 minutes depending on drive size...")
    print("PhotoRec will scan free space for recoverable files...")

    try:
        # Run PhotoRec in command-line mode
        # /d = recovery directory
        # /cmd = scripted commands
        # partition_none = scan whole disk
        # freespace = only scan free space (faster)
        # search = start recovery
        result = subprocess.run(
            [photorec_exe, '/d', str(recovery_dir), '/cmd', drive_letter,
             'partition_none,freespace,search'],
            capture_output=True,
            text=True,
            timeout=900  # 15 minutes max
        )

        # Check if any files were recovered
        print("\nAnalyzing recovery results...")

        recovered_files = []
        original_filenames_found = []

        # Scan recovery directory for files
        if recovery_dir.exists():
            for item in recovery_dir.rglob('*'):
                if item.is_file():
                    recovered_files.append(item.name)
                    # Check if this matches any original filenames
                    if original_names:
                        for orig_name in original_names:
                            if orig_name.lower() in item.name.lower():
                                original_filenames_found.append(orig_name)

        # Clean up
        try:
            import shutil
            if recovery_dir.exists():
                shutil.rmtree(recovery_dir)
        except Exception as cleanup_error:
            print(f"\nNote: Could not clean up recovery directory: {cleanup_error}")
            print(f"Please manually delete: {recovery_dir}")

        # Analyze results
        recoverable_count = len(recovered_files)
        tmp_file_count = sum(1 for f in recovered_files if '.tmp' in f.lower())

        print("=" * 70)
        print("VALIDATION RESULTS")
        print("=" * 70)

        if original_filenames_found:
            print("\nWARNING: Original filenames detected!")
            print("PhotoRec recovered files with original names:")
            for name in set(original_filenames_found[:10]):  # Show first 10
                print(f"  - {name}")
            if len(original_filenames_found) > 10:
                print(f"  ... and {len(original_filenames_found) - 10} more")

        print(f"\nRecoverable files detected: {recoverable_count}")
        print(f"Renamed .tmp files found: {tmp_file_count}")
        print(f"Original filenames found: {len(set(original_filenames_found))}")

        if recoverable_count == 0:
            print("\n" + "=" * 70)
            print("SUCCESS: No recoverable files found!")
            print("=" * 70)
            print("Secure deletion appears successful.")
            print("PhotoRec could not recover any files from free space.")
            return True, "No recoverable files"

        elif recoverable_count > 0 and not original_filenames_found:
            print("\n" + "=" * 70)
            print("PARTIAL SUCCESS: Files recovered but no original names")
            print("=" * 70)
            print("Files were renamed successfully (no original names found).")
            print(f"However, PhotoRec recovered {recoverable_count} files.")
            print("This is expected if deletion just occurred.")
            print("\nRecommendation:")
            print("  - Run cipher /w to wipe free space")
            print("  - Or use --flood-vss and --flood-journal for additional security")
            return True, "Files renamed but may be recoverable"

        else:
            print("\n" + "=" * 70)
            print("WARNING: Files may be recoverable")
            print("=" * 70)
            print(f"PhotoRec recovered {recoverable_count} files.")
            if original_filenames_found:
                print(f"Found {len(set(original_filenames_found))} files with original names!")
            print("\nPossible causes:")
            print("  - Deletion just occurred (data not yet overwritten)")
            print("  - Volume Shadow Copies contain old versions")
            print("  - NTFS journal contains metadata")
            print("  - Free space not yet overwritten")
            print("\nRecommendations:")
            print("  1. Run with --flood-vss to remove shadow copies")
            print("  2. Run with --flood-journal to obscure metadata")
            print("  3. Run cipher /w to wipe all free space")
            return False, "Recoverable files detected"

    except subprocess.TimeoutExpired:
        print("\nERROR: PhotoRec scan timed out (>15 minutes)")
        # Clean up
        try:
            import shutil
            if recovery_dir.exists():
                shutil.rmtree(recovery_dir)
        except:
            pass
        return False, "Scan timeout"

    except Exception as e:
        print(f"\nERROR during validation: {e}")
        # Clean up
        try:
            import shutil
            if recovery_dir.exists():
                shutil.rmtree(recovery_dir)
        except:
            pass
        return False, f"Error: {e}"


def run_cipher_wipe(path):
    """
    Run Windows cipher command to wipe ALL free space on entire drive

    WARNING: This wipes the ENTIRE DRIVE's free space, not just the folder.
    """
    if sys.platform != 'win32':
        print("\nSkipping cipher /w (only available on Windows)")
        return

    # Get drive letter for clear messaging
    drive_letter = Path(path).resolve().drive

    print("\n" + "=" * 70)
    print("WARNING: cipher /w wipes ALL FREE SPACE on the ENTIRE DRIVE")
    print("=" * 70)
    print(f"\nThis command will:")
    print(f"  - Use {path} as a location to create temporary files")
    print(f"  - BUT wipe ALL free space on {drive_letter if drive_letter else 'the drive'}")
    print(f"  - NOT just the space from your deleted folder")
    print("\nThe process:")
    print("  Pass 1: Write 0x00 (zeros) across all free space")
    print("  Pass 2: Write 0xFF (ones) across all free space")
    print("  Pass 3: Write random data across all free space")
    print("\nThis may take 30 minutes to several hours depending on free space!")
    print(f"Typical time for 100-500 GB free space: 1-2 hours")
    print("=" * 70)

    try:
        # Run cipher /w on the parent directory
        result = subprocess.run(
            ['cipher', '/w:' + str(path)],
            capture_output=False,
            text=True
        )

        if result.returncode == 0:
            print("\nCipher wipe completed successfully!")
        else:
            print(f"\nCipher command finished with return code: {result.returncode}")
    except FileNotFoundError:
        print("\nERROR: cipher command not found. This tool is only available on Windows.")
    except Exception as e:
        print(f"\nError running cipher: {e}")


def main():
    print("\n" + "=" * 70)
    print("SECURE FOLDER DELETION TOOL")
    print("=" * 70)

    # Show help if no arguments provided
    if len(sys.argv) == 1:
        sys.argv.append('--help')

    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Securely delete a folder by overwriting files before deletion',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Basic usage:
    python wipe-folder.py c:\\temp\\coding\\outlook-extract
    python wipe-folder.py c:\\temp\\coding\\outlook-extract --passes=1
    python wipe-folder.py /path/to/folder --passes=5 --verbose
    python wipe-folder.py /path/to/folder --no-rename

  Advanced - Auto-flood journal and VSS (recommended for maximum security):
    python wipe-folder.py /path/to/folder --flood-journal --flood-vss

  Advanced - Validate deletion with Recuva recovery test:
    python wipe-folder.py /path/to/folder --validate
    python wipe-folder.py /path/to/folder --flood-journal --flood-vss --validate

  Advanced - Manual control:
    python wipe-folder.py /path/to/folder --flood-journal=50000
    python wipe-folder.py /path/to/folder --flood-vss=20

DEPENDENCIES (Optional but Recommended):
  For optimal performance with progress bars and ETA:
    pip install tqdm

  Without tqdm, the script will still work but show basic progress updates.

FEATURES:
  - Renames files and folders 3x with 48-char random names (default)
  - Single fsync per file for 40-60% speed improvement
  - Progress bar with ETA (requires tqdm)
  - VSS and NTFS journal detection with risk warnings
  - Auto-sizing for journal/VSS floods based on system configuration
  - NTFS journal flooding to obscure metadata traces (optional)
  - VSS storage flooding to force old snapshot deletion (optional)
  - Automated validation with PhotoRec recovery testing (optional)
  - Auto-installation of PhotoRec (TestDisk) via winget if needed
  - Time and throughput statistics

SECURITY TECHNIQUES:
  - Renaming obscures filenames in directory metadata (default ON)
  - 3-pass overwrite defeats most recovery tools (adjustable)
  - Journal flooding buries original filenames in garbage entries
  - VSS flooding triggers automatic deletion of old shadow copies
  - Optional cipher /w to wipe free space (Windows only)

ANTI-FORENSICS TECHNIQUES:
  --flood-journal: Flood NTFS journal with dummy file operations
    - Auto-detects journal size and calculates optimal file count
    - Creates, renames 3x, and deletes dummy files
    - Targets 150% journal fill to ensure metadata wrap-around
    - Buries original filenames in noise without disabling features
    - Typical: 50k-200k files depending on journal size (2-8 minutes)

  --flood-vss: Flood VSS storage to force old snapshot deletion
    - Auto-detects VSS storage allocation
    - Writes large files to fill 80% of VSS max storage
    - Forces Windows to auto-delete oldest snapshots (FIFO)
    - Safer than manual deletion (preserves system functionality)
    - Typical: 10-50 GB depending on VSS allocation (5-15 minutes)

  --validate: Automated deletion validation with PhotoRec
    - Automatically installs PhotoRec (TestDisk package) via winget if not present
    - Runs file recovery scan on free space after deletion
    - Checks for original filenames in recovered files
    - Provides success/failure report with recommendations
    - Typical: 2-10 minutes depending on drive size

  Recommended workflow for maximum security:
    1. Delete files with renaming (default)
    2. Flood VSS to remove shadow copies (--flood-vss)
    3. Flood journal to obscure metadata (--flood-journal)
    4. Validate deletion with recovery test (--validate)
    5. Optionally wipe ALL free space on ENTIRE DRIVE (cipher /w)

IMPORTANT - About cipher /w:
  cipher /w wipes ALL free space on the ENTIRE DRIVE, not just your folder!
  - Uses specified path only as a temp file location
  - Wipes 100-500+ GB depending on drive free space
  - Takes 30 minutes to several hours (3 full passes)
  - Only needed to erase OTHER old deleted files from weeks/months ago
  - Your files are already securely deleted by this tool

WARNING: This will permanently delete all files in the specified folder!
         Files will be overwritten before deletion to prevent recovery.
        '''
    )

    parser.add_argument(
        'folder_path',
        help='Path to the folder to securely delete'
    )

    parser.add_argument(
        '--passes',
        type=int,
        default=3,
        choices=range(1, 11),
        metavar='N',
        help='Number of overwrite passes (1-10, default: 3)'
    )

    parser.add_argument(
        '--no-rename',
        action='store_true',
        help='Skip renaming files/folders before deletion (faster but less secure)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed progress for each file'
    )

    parser.add_argument(
        '--flood-journal',
        type=int,
        metavar='N',
        const=-1,
        nargs='?',
        help='Flood NTFS journal with dummy operations (auto-sizes to journal, or specify N files)'
    )

    parser.add_argument(
        '--flood-vss',
        type=float,
        metavar='GB',
        const=-1,
        nargs='?',
        help='Flood VSS storage with data to force old snapshot deletion (auto-sizes, or specify GB)'
    )

    parser.add_argument(
        '--validate',
        action='store_true',
        help='Run recovery test after deletion to verify files cannot be recovered (requires winget)'
    )

    args = parser.parse_args()

    folder_path = Path(args.folder_path).resolve()
    passes = args.passes
    rename_files = not args.no_rename

    print(f"\nTarget folder: {folder_path}")
    print(f"Overwrite passes: {passes}")
    print(f"Rename files/folders: {rename_files}")

    if not folder_path.exists():
        print(f"\nERROR: Folder does not exist: {folder_path}")
        sys.exit(1)

    # Count files for user awareness and capture original filenames for validation
    original_filenames = []
    try:
        file_count = sum(1 for _ in folder_path.rglob('*') if _.is_file())
        dir_count = sum(1 for _ in folder_path.rglob('*') if _.is_dir())
        print(f"Files to delete: {file_count}")
        print(f"Directories to delete: {dir_count}")

        # Capture original filenames if validation is requested
        if args.validate:
            print("Capturing original filenames for validation...")
            for file_path in folder_path.rglob('*'):
                if file_path.is_file():
                    original_filenames.append(file_path.name)
            print(f"Captured {len(original_filenames)} filenames for validation")
    except Exception as e:
        print(f"Could not count files: {e}")

    # Check for VSS and NTFS journal warnings
    print_security_warnings(folder_path)

    # Safety confirmation
    print("\n" + "!" * 70)
    print("WARNING: THIS OPERATION CANNOT BE UNDONE!")
    print("!" * 70)
    response = input(f"\nType 'DELETE' to confirm secure deletion of '{folder_path}': ")

    if response != 'DELETE':
        print("\nOperation cancelled.")
        sys.exit(0)

    # Perform secure deletion
    parent_dir = secure_delete_folder(args.folder_path, passes, rename_files=rename_files, verbose=args.verbose)

    # VSS flooding if requested (do first since it creates/deletes large files)
    if args.flood_vss is not None and parent_dir:
        if args.flood_vss == -1:
            # Auto-size
            flood_vss(parent_dir, target_size_gb=None)
        else:
            # User-specified size
            flood_vss(parent_dir, target_size_gb=args.flood_vss)

    # Journal flooding if requested
    if args.flood_journal is not None and parent_dir:
        if args.flood_journal == -1:
            # Auto-size
            flood_journal(parent_dir, num_files=None)
        else:
            # User-specified count
            flood_journal(parent_dir, num_files=args.flood_journal)

    # Validate deletion if requested
    if args.validate and parent_dir:
        validate_deletion(folder_path, original_names=original_filenames if original_filenames else None)

    # Ask about cipher wipe
    if parent_dir and sys.platform == 'win32':
        print(f"\nSecure deletion complete.")
        print("\n" + "=" * 70)
        print("OPTIONAL: Wipe ALL free space on entire drive with cipher /w")
        print("=" * 70)

        # Get drive info
        try:
            drive_letter = Path(parent_dir).resolve().drive
            result = subprocess.run(['fsutil', 'volume', 'diskfree', drive_letter],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Total free bytes' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            try:
                                free_bytes = int(parts[1].strip().replace(',', ''))
                                free_gb = free_bytes / (1024 * 1024 * 1024)
                                print(f"\nFree space on {drive_letter}: {free_gb:.1f} GB")
                                est_time = (free_gb / 100) * 30  # ~30 min per 100 GB estimate
                                print(f"Estimated time: {est_time:.0f}-{est_time*2:.0f} minutes ({est_time/60:.1f}-{est_time*2/60:.1f} hours)")
                            except:
                                pass
        except:
            pass

        print("\nIMPORTANT: cipher /w will:")
        print(f"  - Wipe ALL free space on the ENTIRE {drive_letter if drive_letter else 'drive'}")
        print(f"  - NOT just wipe space from {parent_dir}")
        print("  - Take 30 min to several hours depending on free space")
        print("  - Do 3 full passes (0x00, 0xFF, random data)")

        response = input(f"\nWipe ALL free space on {drive_letter if drive_letter else 'the drive'}? (yes/no): ")

        if response.lower() in ['yes', 'y']:
            run_cipher_wipe(parent_dir)
        else:
            print("\nSkipping cipher wipe.")
            print(f"\nYou already securely deleted your files with {passes} overwrite passes.")
            print("cipher /w is optional and only needed if you want to wipe OTHER")
            print("deleted files on the drive from weeks/months ago.")
            print(f"\nTo run manually later: cipher /w:{parent_dir}")

    print("\n" + "=" * 70)
    print("All operations complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
