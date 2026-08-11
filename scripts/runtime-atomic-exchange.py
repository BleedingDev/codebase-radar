#!/usr/bin/env python3
"""Trusted atomic publication helper for analyzer runtime generations.

The shell never renames the authoritative runtime itself.  This helper writes a
durable same-parent journal, fsyncs the fully verified candidate, performs one
Linux renameat2(RENAME_EXCHANGE), and leaves the former generation beside the
new authoritative path until recovery has observed a coherent inode pair.
"""

import ctypes
from contextlib import contextmanager
import errno
try:
    import fcntl
except ImportError:
    fcntl = None
import json
import os
import platform
import posixpath
import secrets
import shutil
import stat
import sys
import tarfile
import tempfile


AT_FDCWD = -100
RENAME_EXCHANGE = 0x2
SYS_RENAMEAT2_X86_64 = 316
JOURNAL_VERSION = 1
COPY_MAX_ENTRIES = 100_000
COPY_MAX_DEPTH = 64
COPY_MAX_FILE_BYTES = 256 * 1024 * 1024
COPY_MAX_AGGREGATE_BYTES = 1024 * 1024 * 1024
COPY_MAX_SYMLINK_BYTES = 4096
COPY_ENTRY_METADATA_BYTES = 256
COPY_CHUNK_BYTES = 64 * 1024
COPY_MAX_GENERATED_BIN_ENTRIES = 256
COPY_MAX_GENERATED_BIN_BYTES = 4 * 1024 * 1024
TAR_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def fail(code: str, message: str) -> None:
    sys.stderr.write("[runtime:" + code + "] " + message + "\n")
    raise SystemExit(1)


def require_absolute(path: str, label: str) -> str:
    if not path or not os.path.isabs(path):
        fail("atomic-path-invalid", label + " must be an absolute path.")
    if "\x00" in path:
        fail("atomic-path-invalid", label + " contains a NUL byte.")
    return path


def lstat_directory(path: str, label: str) -> os.stat_result:
    require_absolute(path, label)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail("atomic-path-missing", label + " is missing: " + path + ".")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("atomic-path-invalid", label + " must be a non-symlink directory: " + path + ".")
    return metadata


def lstat_regular_file(path: str, label: str) -> os.stat_result:
    require_absolute(path, label)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail("journal-missing", label + " is missing: " + path + ".")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("journal-invalid", label + " must be a regular non-symlink file.")
    if metadata.st_nlink != 1:
        fail("journal-invalid", label + " must not be hard-linked.")
    return metadata


def open_directory(path: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags)


def metadata_identity(metadata: os.stat_result) -> tuple:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def validate_copy_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        fail("source-copy-entry-invalid", "Runtime source contains an invalid entry name.")
    try:
        encoded = name.encode("utf-8", "strict")
    except UnicodeEncodeError:
        fail("source-copy-entry-invalid", "Runtime source contains a non-UTF-8 entry name.")
    if len(encoded) > 255:
        fail("source-copy-entry-invalid", "Runtime source contains an oversized entry name.")


def validate_copy_symlink(target: str, parent_relative: str) -> bytes:
    if (
        not target
        or target.startswith("/")
        or "\\" in target
        or any(ord(character) < 32 or ord(character) == 127 for character in target)
    ):
        fail("source-copy-symlink-invalid", "Runtime source contains an unsafe symlink target.")
    try:
        encoded = target.encode("utf-8", "strict")
    except UnicodeEncodeError:
        fail("source-copy-symlink-invalid", "Runtime source contains a non-UTF-8 symlink target.")
    if len(encoded) > COPY_MAX_SYMLINK_BYTES:
        fail("source-copy-symlink-invalid", "Runtime source contains an oversized symlink target.")
    resolved = posixpath.normpath(posixpath.join(parent_relative, target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        fail("source-copy-symlink-invalid", "Runtime source contains a symlink escaping its root.")
    return encoded


class CopyBudget:
    def __init__(self) -> None:
        self.entries = 0
        self.bytes = 0

    def reserve(self, payload_bytes: int) -> None:
        self.entries += 1
        if self.entries > COPY_MAX_ENTRIES:
            fail("source-copy-entry-limit", "Runtime source exceeds its bounded entry count.")
        self.bytes += COPY_ENTRY_METADATA_BYTES + payload_bytes
        if self.bytes > COPY_MAX_AGGREGATE_BYTES:
            fail("source-copy-byte-limit", "Runtime source exceeds its bounded aggregate byte count.")


def open_child_directory(parent_descriptor: int, name: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return os.open(name, flags, dir_fd=parent_descriptor)


def is_generated_package_directory(relative_path: str, generated_name: str) -> bool:
    parts = relative_path.split("/")
    if len(parts) == 7:
        return (
            parts[0:2] == ["node_modules", ".pnpm"]
            and parts[3] == "node_modules"
            and not parts[4].startswith("@")
            and parts[5:7] == ["node_modules", generated_name]
        )
    if len(parts) == 8:
        return (
            parts[0:2] == ["node_modules", ".pnpm"]
            and parts[3] == "node_modules"
            and parts[4].startswith("@")
            and parts[6:8] == ["node_modules", generated_name]
        )
    return False


def validate_omitted_generated_package_bins(
    directory: int,
    relative_path: str,
    budget: CopyBudget,
) -> None:
    before = os.fstat(directory)
    if not stat.S_ISDIR(before.st_mode):
        fail("source-copy-generated-bin-invalid", "Generated package executable directory is invalid.")
    try:
        names = sorted(os.listdir(directory))
    except OSError as error:
        fail("source-copy-generated-bin-invalid", "Generated package executables could not be listed: " + str(error) + ".")
    if len(names) > COPY_MAX_GENERATED_BIN_ENTRIES:
        fail("source-copy-generated-bin-invalid", "Generated package executables exceed their bounded entry count.")
    generated_bytes = 0
    for name in names:
        validate_copy_name(name)
        try:
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except OSError as error:
            fail("source-copy-changed", "Generated package executable disappeared before validation: " + str(error) + ".")
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_nlink != 1
            or stat.S_IMODE(named.st_mode) & 0o7000
            or named.st_size < 0
        ):
            fail("source-copy-generated-bin-invalid", "Generated package executable must be an independent regular file.")
        generated_bytes += named.st_size
        if generated_bytes > COPY_MAX_GENERATED_BIN_BYTES:
            fail("source-copy-generated-bin-invalid", "Generated package executables exceed their bounded byte count.")
        budget.reserve(named.st_size)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(name, flags, dir_fd=directory)
        except OSError as error:
            fail("source-copy-changed", "Generated package executable could not be opened safely: " + str(error) + ".")
        try:
            opened = os.fstat(descriptor)
            if metadata_identity(opened) != metadata_identity(named):
                fail("source-copy-changed", "Generated package executable changed before it was opened.")
            offset = 0
            while offset < opened.st_size:
                requested = min(COPY_CHUNK_BYTES, opened.st_size - offset)
                chunk = os.pread(descriptor, requested, offset)
                if len(chunk) != requested:
                    fail("source-copy-changed", "Generated package executable changed while it was read.")
                offset += len(chunk)
            after_descriptor = os.fstat(descriptor)
            after_name = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                metadata_identity(opened) != metadata_identity(after_descriptor)
                or metadata_identity(opened) != metadata_identity(after_name)
            ):
                fail("source-copy-changed", "Generated package executable changed while it was validated.")
        finally:
            os.close(descriptor)
    try:
        after_names = sorted(os.listdir(directory))
    except OSError as error:
        fail("source-copy-generated-bin-invalid", "Generated package executables could not be relisted: " + str(error) + ".")
    if names != after_names or metadata_identity(before) != metadata_identity(os.fstat(directory)):
        fail("source-copy-changed", "Generated package executable directory changed while it was validated.")


def validate_omitted_generated_package_temp(
    directory: int,
) -> None:
    before = os.fstat(directory)
    if not stat.S_ISDIR(before.st_mode):
        fail("source-copy-generated-temp-invalid", "Generated package temporary directory is invalid.")
    try:
        names = os.listdir(directory)
    except OSError as error:
        fail("source-copy-generated-temp-invalid", "Generated package temporary directory could not be listed: " + str(error) + ".")
    if names:
        fail("source-copy-generated-temp-invalid", "Generated package temporary directory must be empty.")
    if metadata_identity(before) != metadata_identity(os.fstat(directory)):
        fail("source-copy-changed", "Generated package temporary directory changed while it was validated.")


def copy_regular_file(
    source_parent: int,
    destination_parent: int,
    name: str,
    before: os.stat_result,
    budget: CopyBudget,
) -> None:
    if before.st_nlink != 1 or before.st_size < 0 or before.st_size > COPY_MAX_FILE_BYTES:
        fail("source-copy-file-invalid", "Runtime source contains an oversized or multiply linked file.")
    budget.reserve(before.st_size)
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        source_flags |= os.O_CLOEXEC
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        destination_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        destination_flags |= os.O_CLOEXEC
    try:
        source = os.open(name, source_flags, dir_fd=source_parent)
    except OSError as error:
        fail("source-copy-changed", "Runtime source file could not be opened safely: " + str(error) + ".")
    destination = None
    try:
        opened = os.fstat(source)
        if metadata_identity(opened) != metadata_identity(before):
            fail("source-copy-changed", "Runtime source file changed before it was opened.")
        try:
            destination = os.open(name, destination_flags, 0o600, dir_fd=destination_parent)
        except OSError as error:
            fail("source-copy-destination-invalid", "Runtime stage file could not be created exclusively: " + str(error) + ".")
        offset = 0
        while offset < opened.st_size:
            requested = min(COPY_CHUNK_BYTES, opened.st_size - offset)
            chunk = os.pread(source, requested, offset)
            if len(chunk) != requested:
                fail("source-copy-changed", "Runtime source file changed while it was read.")
            write_all(destination, chunk)
            offset += len(chunk)
        after_descriptor = os.fstat(source)
        after_name = os.stat(name, dir_fd=source_parent, follow_symlinks=False)
        if (
            metadata_identity(opened) != metadata_identity(after_descriptor)
            or metadata_identity(opened) != metadata_identity(after_name)
        ):
            fail("source-copy-changed", "Runtime source file changed while it was copied.")
        os.fchmod(destination, stat.S_IMODE(opened.st_mode))
        os.fsync(destination)
    finally:
        if destination is not None:
            os.close(destination)
        os.close(source)


def copy_directory_contents(
    source: int,
    destination: int,
    relative_path: str,
    depth: int,
    budget: CopyBudget,
) -> None:
    if depth > COPY_MAX_DEPTH:
        fail("source-copy-depth-limit", "Runtime source exceeds its bounded directory depth.")
    source_before = os.fstat(source)
    if not stat.S_ISDIR(source_before.st_mode):
        fail("source-copy-directory-invalid", "Runtime source directory descriptor is invalid.")
    try:
        before_names = sorted(os.listdir(source))
    except OSError as error:
        fail("source-copy-directory-invalid", "Runtime source directory could not be listed: " + str(error) + ".")
    for name in before_names:
        validate_copy_name(name)
        try:
            before = os.stat(name, dir_fd=source, follow_symlinks=False)
        except OSError as error:
            fail("source-copy-changed", "Runtime source entry disappeared before copy: " + str(error) + ".")
        mode = before.st_mode
        if not stat.S_ISLNK(mode) and stat.S_IMODE(mode) & 0o7000:
            fail("source-copy-mode-invalid", "Runtime source contains special permission bits.")
        if stat.S_ISREG(mode):
            copy_regular_file(source, destination, name, before, budget)
            continue
        if stat.S_ISDIR(mode):
            budget.reserve(0)
            child_relative = name if relative_path == "" else relative_path + "/" + name
            is_generated_bin = is_generated_package_directory(child_relative, ".bin")
            is_generated_temp = is_generated_package_directory(child_relative, ".tmp")
            if is_generated_bin or is_generated_temp:
                try:
                    source_child = open_child_directory(source, name)
                except OSError as error:
                    code = "source-copy-generated-bin-invalid" if is_generated_bin else "source-copy-generated-temp-invalid"
                    fail(code, "Generated package directory could not be opened safely: " + str(error) + ".")
                try:
                    opened = os.fstat(source_child)
                    if metadata_identity(opened) != metadata_identity(before):
                        fail("source-copy-changed", "Generated package directory changed before it was opened.")
                    if is_generated_bin:
                        validate_omitted_generated_package_bins(
                            source_child,
                            child_relative,
                            budget,
                        )
                    else:
                        validate_omitted_generated_package_temp(source_child)
                    after_name = os.stat(name, dir_fd=source, follow_symlinks=False)
                    if metadata_identity(opened) != metadata_identity(after_name):
                        fail("source-copy-changed", "Generated package directory changed while it was omitted.")
                finally:
                    os.close(source_child)
                continue
            try:
                os.mkdir(name, 0o700, dir_fd=destination)
                source_child = open_child_directory(source, name)
                destination_child = open_child_directory(destination, name)
            except OSError as error:
                fail("source-copy-directory-invalid", "Runtime source directory could not be opened safely: " + str(error) + ".")
            try:
                opened = os.fstat(source_child)
                if metadata_identity(opened) != metadata_identity(before):
                    fail("source-copy-changed", "Runtime source directory changed before it was opened.")
                copy_directory_contents(
                    source_child,
                    destination_child,
                    child_relative,
                    depth + 1,
                    budget,
                )
                after_name = os.stat(name, dir_fd=source, follow_symlinks=False)
                if metadata_identity(opened) != metadata_identity(after_name):
                    fail("source-copy-changed", "Runtime source directory changed while it was copied.")
                os.fchmod(destination_child, stat.S_IMODE(opened.st_mode))
                os.fsync(destination_child)
            finally:
                os.close(destination_child)
                os.close(source_child)
            continue
        if stat.S_ISLNK(mode):
            if before.st_nlink != 1:
                fail("source-copy-symlink-invalid", "Runtime source contains a multiply linked symlink.")
            try:
                target = os.readlink(name, dir_fd=source)
            except OSError as error:
                fail("source-copy-symlink-invalid", "Runtime source symlink could not be read: " + str(error) + ".")
            parent_relative = relative_path
            encoded = validate_copy_symlink(target, parent_relative)
            budget.reserve(len(encoded))
            try:
                os.symlink(target, name, dir_fd=destination)
                after = os.stat(name, dir_fd=source, follow_symlinks=False)
            except OSError as error:
                fail("source-copy-symlink-invalid", "Runtime source symlink could not be copied safely: " + str(error) + ".")
            if metadata_identity(before) != metadata_identity(after):
                fail("source-copy-changed", "Runtime source symlink changed while it was copied.")
            continue
        fail("source-copy-entry-invalid", "Runtime source contains a special file.")
    try:
        after_names = sorted(os.listdir(source))
    except OSError as error:
        fail("source-copy-directory-invalid", "Runtime source directory could not be relisted: " + str(error) + ".")
    source_after = os.fstat(source)
    if before_names != after_names or metadata_identity(source_before) != metadata_identity(source_after):
        fail("source-copy-changed", "Runtime source directory changed while it was copied.")


def copy_runtime_source(source_root: str, destination_root: str) -> None:
    require_absolute(source_root, "runtime source")
    require_absolute(destination_root, "runtime stage")
    if source_root == destination_root:
        fail("source-copy-path-invalid", "Runtime source and stage must differ.")
    source_named_before = lstat_directory(source_root, "runtime source")
    destination_named = lstat_directory(destination_root, "runtime stage")
    if stat.S_IMODE(source_named_before.st_mode) & 0o7000:
        fail("source-copy-mode-invalid", "Runtime source root contains special permission bits.")
    if os.listdir(destination_root):
        fail("source-copy-destination-invalid", "Runtime stage must be a fresh empty directory.")
    source = open_directory(source_root)
    destination = open_directory(destination_root)
    try:
        source_opened = os.fstat(source)
        if metadata_identity(source_named_before) != metadata_identity(source_opened):
            fail("source-copy-changed", "Runtime source root changed before it was opened.")
        if metadata_identity(destination_named) != metadata_identity(os.fstat(destination)):
            fail("source-copy-destination-invalid", "Runtime stage changed before it was opened.")
        budget = CopyBudget()
        copy_directory_contents(source, destination, "", 0, budget)
        source_named_after = os.lstat(source_root)
        if metadata_identity(source_opened) != metadata_identity(source_named_after):
            fail("source-copy-changed", "Runtime source root changed while it was copied.")
        os.fchmod(destination, stat.S_IMODE(source_opened.st_mode))
        os.fsync(destination)
    finally:
        os.close(destination)
        os.close(source)
    fsync_directory(parent_of(destination_root))


def validate_tar_gz_member(archive_path: str, expected_member: str, maximum_member_bytes_text: str) -> None:
    require_absolute(archive_path, "analyzer archive")
    if (
        not expected_member
        or "/" in expected_member
        or "\\" in expected_member
        or expected_member in {".", ".."}
        or any(ord(character) < 32 or ord(character) == 127 for character in expected_member)
    ):
        fail("archive-member-invalid", "Expected analyzer archive member name is invalid.")
    try:
        maximum_member_bytes = int(maximum_member_bytes_text, 10)
    except ValueError:
        fail("archive-member-limit-invalid", "Analyzer archive member limit is invalid.")
    if maximum_member_bytes < 1 or maximum_member_bytes > COPY_MAX_FILE_BYTES:
        fail("archive-member-limit-invalid", "Analyzer archive member limit is outside the reviewed bound.")
    before = lstat_regular_file(archive_path, "analyzer archive")
    if before.st_size < 1 or before.st_size > TAR_MAX_ARCHIVE_BYTES:
        fail("archive-size-invalid", "Analyzer archive is outside the reviewed compressed-byte bound.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(archive_path, flags)
    try:
        opened = os.fstat(descriptor)
        if metadata_identity(before) != metadata_identity(opened):
            fail("archive-changed", "Analyzer archive changed before bounded header validation.")
        count = 0
        try:
            with os.fdopen(os.dup(descriptor), "rb", closefd=True) as archive_file:
                with tarfile.open(fileobj=archive_file, mode="r|gz") as archive:
                    for member in archive:
                        count += 1
                        if (
                            count != 1
                            or member.name != expected_member
                            or not member.isreg()
                            or member.size < 1
                            or member.size > maximum_member_bytes
                        ):
                            fail(
                                "archive-member-invalid",
                                "Analyzer archive must contain exactly one bounded regular member.",
                            )
        except (tarfile.TarError, EOFError, OSError) as error:
            fail("archive-invalid", "Analyzer archive could not be validated safely: " + str(error) + ".")
        if count != 1:
            fail("archive-member-invalid", "Analyzer archive must contain exactly one bounded regular member.")
        after_descriptor = os.fstat(descriptor)
        after_name = os.lstat(archive_path)
        if (
            metadata_identity(opened) != metadata_identity(after_descriptor)
            or metadata_identity(opened) != metadata_identity(after_name)
        ):
            fail("archive-changed", "Analyzer archive changed during bounded header validation.")
    finally:
        os.close(descriptor)


def fsync_directory(path: str) -> None:
    descriptor = open_directory(path)
    try:
        os.fsync(descriptor)
    except OSError as error:
        fail("atomic-fsync-failed", "Cannot fsync directory " + path + ": " + str(error) + ".")
    finally:
        os.close(descriptor)


def fsync_regular_file(path: str) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail("atomic-fsync-failed", "Cannot open staged file " + path + ": " + str(error) + ".")
    try:
        os.fsync(descriptor)
    except OSError as error:
        fail("atomic-fsync-failed", "Cannot fsync staged file " + path + ": " + str(error) + ".")
    finally:
        os.close(descriptor)


def fsync_tree(root: str) -> None:
    lstat_directory(root, "staged runtime")
    for directory, names, files in os.walk(root, topdown=False, followlinks=False):
        for name in sorted(files):
            path = os.path.join(directory, name)
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                fail("atomic-stage-invalid", "Staged runtime has unsupported entry " + path + ".")
            fsync_regular_file(path)
        for name in sorted(names):
            path = os.path.join(directory, name)
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                fail("atomic-stage-invalid", "Staged runtime has unsupported entry " + path + ".")
        fsync_directory(directory)


def parent_of(path: str) -> str:
    return os.path.dirname(path.rstrip(os.sep)) or os.sep


def require_same_parent(*paths: str) -> str:
    parents = {parent_of(path) for path in paths}
    if len(parents) != 1:
        fail("atomic-parent-invalid", "Runtime, staged generation, and journal must be direct siblings.")
    parent = parents.pop()
    lstat_directory(parent, "runtime parent")
    return parent


def publication_lock_path(journal: str) -> str:
    return journal + ".lock"


def validate_publication_lock(parent: str, lock: str, descriptor: int) -> None:
    parent_metadata = lstat_directory(parent, "runtime parent")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o022:
        fail(
            "publication-lock-invalid",
            "Runtime parent must not be writable by group or other users while publishing.",
        )
    metadata = os.fstat(descriptor)
    try:
        named_metadata = os.lstat(lock)
    except OSError as error:
        fail("publication-lock-invalid", "Cannot inspect publication lock: " + str(error) + ".")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != parent_metadata.st_uid
        or named_metadata.st_dev != metadata.st_dev
        or named_metadata.st_ino != metadata.st_ino
    ):
        fail(
            "publication-lock-invalid",
            "Publication lock must be a private regular file owned by the trusted runtime parent owner.",
        )


@contextmanager
def publication_lock(parent: str, journal: str):
    if fcntl is None or not hasattr(os, "O_NOFOLLOW"):
        fail(
            "publication-lock-unavailable",
            "A no-follow advisory publication lock is required on this host.",
        )
    lock = publication_lock_path(journal)
    if parent_of(lock) != parent:
        fail("publication-lock-invalid", "Publication lock is not a direct child of the trusted runtime parent.")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(lock, flags, 0o600)
    except OSError as error:
        fail("publication-lock-unavailable", "Cannot open publication lock: " + str(error) + ".")
    try:
        validate_publication_lock(parent, lock, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    try:
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError as error:
            fail("publication-lock-failed", "Cannot release publication lock: " + str(error) + ".")
        finally:
            try:
                os.close(descriptor)
            except OSError as error:
                fail("publication-lock-failed", "Cannot close publication lock: " + str(error) + ".")


def inode_record(path: str, label: str) -> dict:
    metadata = lstat_directory(path, label)
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def same_inode(left: dict, right: dict) -> bool:
    return left.get("device") == right.get("device") and left.get("inode") == right.get("inode")


def require_linux_exchange() -> None:
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        fail("atomic-exchange-unavailable", "renameat2 exchange is required on Linux x86_64.")
    if ctypes.sizeof(ctypes.c_long) != 8:
        fail("atomic-exchange-unavailable", "Unsupported Linux syscall ABI.")


def rename_exchange(left: str, right: str) -> None:
    require_linux_exchange()
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        ctypes.c_long(SYS_RENAMEAT2_X86_64),
        ctypes.c_int(AT_FDCWD),
        ctypes.c_char_p(os.fsencode(left)),
        ctypes.c_int(AT_FDCWD),
        ctypes.c_char_p(os.fsencode(right)),
        ctypes.c_uint(RENAME_EXCHANGE),
    )
    if result != 0:
        error = ctypes.get_errno()
        fail(
            "atomic-exchange-unavailable",
            "renameat2(RENAME_EXCHANGE) failed: " + os.strerror(error) + ".",
        )


def journal_payload(runtime: str, stage: str, generation: str, state: str, old: dict, candidate: dict) -> dict:
    return {
        "version": JOURNAL_VERSION,
        "generation": generation,
        "state": state,
        "runtime": runtime,
        "stage": stage,
        "old": old,
        "candidate": candidate,
    }


def write_all(descriptor: int, encoded: bytes) -> None:
    remaining = memoryview(encoded)
    while remaining:
        written = os.write(descriptor, remaining)
        if not isinstance(written, int) or written <= 0 or written > len(remaining):
            raise OSError(errno.EIO, "journal write made no progress")
        remaining = remaining[written:]


def write_journal(journal: str, payload: dict) -> None:
    parent = parent_of(journal)
    lstat_directory(parent, "journal parent")
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temporary = journal + ".new." + str(os.getpid()) + "." + secrets.token_hex(8)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except OSError as error:
        fail("journal-write-failed", "Cannot create journal generation: " + str(error) + ".")
    write_error = None
    try:
        write_all(descriptor, encoded)
        os.fsync(descriptor)
    except OSError as error:
        write_error = error
    try:
        os.close(descriptor)
    except OSError as error:
        if write_error is None:
            write_error = error
    if write_error is not None:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        fail("journal-write-failed", "Cannot write journal generation: " + str(write_error) + ".")
    try:
        os.replace(temporary, journal)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        fail("journal-write-failed", "Cannot publish journal generation: " + str(error) + ".")
    fsync_directory(parent)


def read_journal(journal: str):
    if not os.path.lexists(journal):
        return None
    lstat_regular_file(journal, "publication journal")
    try:
        with open(journal, "rb") as handle:
            decoded = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail("journal-invalid", "Cannot read publication journal: " + str(error) + ".")
    if not isinstance(decoded, dict) or set(decoded) != {
        "version",
        "generation",
        "state",
        "runtime",
        "stage",
        "old",
        "candidate",
    }:
        fail("journal-invalid", "Publication journal has an unexpected schema.")
    if (
        decoded["version"] != JOURNAL_VERSION
        or decoded["state"] not in {"prepared", "exchanged"}
        or not isinstance(decoded["generation"], str)
        or len(decoded["generation"]) != 32
        or not isinstance(decoded["runtime"], str)
        or not isinstance(decoded["stage"], str)
    ):
        fail("journal-invalid", "Publication journal has invalid generation metadata.")
    for field in ("old", "candidate"):
        value = decoded[field]
        if not isinstance(value, dict) or set(value) != {"device", "inode"}:
            fail("journal-invalid", "Publication journal has invalid inode metadata.")
        if not isinstance(value["device"], int) or not isinstance(value["inode"], int):
            fail("journal-invalid", "Publication journal has invalid inode values.")
    return decoded


def remove_tree(parent: str, candidate: str, label: str) -> None:
    if parent_of(candidate) != parent:
        fail("cleanup-invalid", label + " is not a direct child of its trusted parent.")
    metadata = lstat_directory(candidate, label)
    if not shutil.rmtree.avoids_symlink_attacks:
        fail("cleanup-unavailable", "The host Python lacks symlink-safe recursive removal.")
    descriptor = open_directory(parent)
    try:
        shutil.rmtree(os.path.basename(candidate), dir_fd=descriptor)
    except OSError as error:
        fail("cleanup-failed", "Cannot remove " + label + ": " + str(error) + ".")
    finally:
        os.close(descriptor)
    fsync_directory(parent)


def remove_journal(parent: str, journal: str) -> None:
    if parent_of(journal) != parent:
        fail("cleanup-invalid", "Publication journal is not a direct child of its trusted parent.")
    if not os.path.lexists(journal):
        return
    lstat_regular_file(journal, "publication journal")
    descriptor = open_directory(parent)
    try:
        os.unlink(os.path.basename(journal), dir_fd=descriptor)
    except OSError as error:
        fail("cleanup-failed", "Cannot remove publication journal: " + str(error) + ".")
    finally:
        os.close(descriptor)
    fsync_directory(parent)


def recover(runtime: str, journal: str) -> None:
    require_absolute(runtime, "authoritative runtime")
    require_absolute(journal, "publication journal")
    parent = require_same_parent(runtime, journal, publication_lock_path(journal))
    with publication_lock(parent, journal):
        payload = read_journal(journal)
        if payload is None:
            return
        if payload["runtime"] != runtime:
            fail("journal-invalid", "Publication journal does not belong to this authoritative runtime.")
        stage = payload["stage"]
        require_absolute(stage, "staged runtime")
        require_same_parent(runtime, stage, journal, publication_lock_path(journal))
        current = inode_record(runtime, "authoritative runtime")
        stage_exists = os.path.lexists(stage)
        if stage_exists:
            staged = inode_record(stage, "staged runtime")
            if same_inode(current, payload["old"]) and same_inode(staged, payload["candidate"]):
                remove_tree(parent, stage, "unpublished staged runtime")
                remove_journal(parent, journal)
                return
            if same_inode(current, payload["candidate"]) and same_inode(staged, payload["old"]):
                remove_tree(parent, stage, "previous runtime generation")
                remove_journal(parent, journal)
                return
            fail("journal-ambiguous", "Publication journal inode generation does not match either safe recovery state.")
        if payload["state"] == "exchanged" and same_inode(current, payload["candidate"]):
            remove_journal(parent, journal)
            return
        fail("journal-ambiguous", "Publication journal is missing its sibling generation before a durable exchanged state.")


def fresh_directory(parent: str, prefix: str) -> None:
    require_absolute(parent, "runtime parent")
    if not prefix or "/" in prefix or "\\" in prefix or any(ord(char) < 32 or ord(char) == 127 for char in prefix):
        fail("temporary-root-invalid", "Temporary directory prefix is invalid.")
    lstat_directory(parent, "runtime parent")
    candidate = tempfile.mkdtemp(prefix=prefix, dir=parent)
    metadata = lstat_directory(candidate, "fresh temporary directory")
    if parent_of(candidate) != parent or metadata.st_dev != lstat_directory(parent, "runtime parent").st_dev:
        fail("temporary-root-invalid", "Temporary directory is not a same-parent generation.")
    fsync_directory(parent)
    sys.stdout.write(candidate + "\n")


def remove_directory(parent: str, candidate: str) -> None:
    require_absolute(parent, "runtime parent")
    require_absolute(candidate, "temporary runtime directory")
    lstat_directory(parent, "runtime parent")
    remove_tree(parent, candidate, "temporary runtime directory")


def assert_exchange_available(parent: str) -> None:
    require_linux_exchange()
    lstat_directory(parent, "runtime parent")
    left = tempfile.mkdtemp(prefix=".analyzer-runtime-exchange-left.", dir=parent)
    right = tempfile.mkdtemp(prefix=".analyzer-runtime-exchange-right.", dir=parent)
    try:
        with open(os.path.join(left, "sentinel"), "wb") as handle:
            handle.write(b"old\n")
            handle.flush()
            os.fsync(handle.fileno())
        with open(os.path.join(right, "sentinel"), "wb") as handle:
            handle.write(b"new\n")
            handle.flush()
            os.fsync(handle.fileno())
        fsync_directory(left)
        fsync_directory(right)
        fsync_directory(parent)
        rename_exchange(left, right)
        fsync_directory(parent)
        with open(os.path.join(left, "sentinel"), "rb") as handle:
            if handle.read() != b"new\n":
                fail("atomic-exchange-unavailable", "Exchange capability probe did not swap the left generation.")
        with open(os.path.join(right, "sentinel"), "rb") as handle:
            if handle.read() != b"old\n":
                fail("atomic-exchange-unavailable", "Exchange capability probe did not swap the right generation.")
    finally:
        for candidate in (left, right):
            if os.path.lexists(candidate):
                remove_tree(parent, candidate, "exchange capability probe")


def publish(runtime: str, stage: str, journal: str) -> None:
    require_absolute(runtime, "authoritative runtime")
    require_absolute(stage, "staged runtime")
    require_absolute(journal, "publication journal")
    if runtime == stage:
        fail("atomic-path-invalid", "Authoritative and staged runtime paths must differ.")
    parent = require_same_parent(runtime, stage, journal, publication_lock_path(journal))
    with publication_lock(parent, journal):
        if os.path.lexists(journal):
            fail("journal-present", "Recover a prior publication journal before publishing another generation.")
        old = inode_record(runtime, "authoritative runtime")
        candidate = inode_record(stage, "staged runtime")
        if old["device"] != candidate["device"]:
            fail("atomic-device-mismatch", "Authoritative and staged runtime must share a filesystem.")
        fsync_tree(stage)
        fsync_directory(stage)
        fsync_directory(runtime)
        fsync_directory(parent)
        generation = secrets.token_hex(16)
        payload = journal_payload(runtime, stage, generation, "prepared", old, candidate)
        write_journal(journal, payload)
        rename_exchange(runtime, stage)
        fsync_directory(parent)
        fsync_directory(runtime)
        fsync_directory(stage)
        write_journal(
            journal,
            journal_payload(runtime, stage, generation, "exchanged", old, candidate),
        )


def exchange(left: str, right: str) -> None:
    require_absolute(left, "left generation")
    require_absolute(right, "right generation")
    parent = require_same_parent(left, right)
    lstat_directory(left, "left generation")
    lstat_directory(right, "right generation")
    rename_exchange(left, right)
    fsync_directory(parent)


def usage() -> None:
    fail(
        "atomic-usage",
        "Expected one of: fresh-dir PARENT PREFIX; copy-source SOURCE DESTINATION; validate-tar-gz-member ARCHIVE MEMBER MAXIMUM_BYTES; remove-dir PARENT CANDIDATE; recover RUNTIME JOURNAL; publish RUNTIME STAGE JOURNAL; assert-available PARENT; exchange LEFT RIGHT.",
    )


def main() -> None:
    if len(sys.argv) < 2:
        usage()
    command = sys.argv[1]
    args = sys.argv[2:]
    if command == "fresh-dir" and len(args) == 2:
        fresh_directory(args[0], args[1])
        return
    if command == "copy-source" and len(args) == 2:
        copy_runtime_source(args[0], args[1])
        return
    if command == "validate-tar-gz-member" and len(args) == 3:
        validate_tar_gz_member(args[0], args[1], args[2])
        return
    if command == "remove-dir" and len(args) == 2:
        remove_directory(args[0], args[1])
        return
    if command == "recover" and len(args) == 2:
        recover(args[0], args[1])
        return
    if command == "publish" and len(args) == 3:
        publish(args[0], args[1], args[2])
        return
    if command == "assert-available" and len(args) == 1:
        assert_exchange_available(args[0])
        return
    if command == "exchange" and len(args) == 2:
        exchange(args[0], args[1])
        return
    usage()


if __name__ == "__main__":
    main()
