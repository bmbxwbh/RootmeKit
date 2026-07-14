"""Python-native Android OTA payload.bin parser.

Extracts partition images (e.g. init_boot, boot) from Android OTA
payload.bin files without depending on external tools like payload-dumper-go.

Supports two payload formats:
  1. **BrilloUpdatePayload** (legacy): magic = ``BrilloUpdatePayload``
  2. **CrAU** (modern, Chrome OS Update Engine v2): magic = ``CrAU``

CrAU v2 format (used by modern Xiaomi, OnePlus, etc.):
  [4 bytes]  magic = ``CrAU``
  [8 bytes]  format_version (big-endian uint64) — typically 2
  [8 bytes]  manifest_size (big-endian uint64)
  [32 bytes] metadata_signature (SHA-256, can be ignored)
  [manifest_size bytes] DeltaArchiveManifest (protobuf)
  [remaining bytes] data blobs

BrilloUpdatePayload format (legacy):
  [20 bytes] magic = ``BrilloUpdatePayload``
  [8 bytes]  header_length (big-endian uint64)
  [header_length bytes] DeltaArchiveManifest (protobuf)
  [remaining bytes] data blobs

Minimal protobuf wire format decoding is implemented inline — no protobuf
library dependency required.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

PAYLOAD_MAGIC_BRILLO = b"BrilloUpdatePayload"
PAYLOAD_MAGIC_CRAU = b"CrAU"

# Protobuf wire types
_WIRE_VARINT = 0
_WIRE_64BIT = 1
_WIRE_LENGTH_DELIMITED = 2
_WIRE_32BIT = 5

# ---------------------------------------------------------------------------
# Universal decompression dispatcher
# Detects actual compression format from blob magic bytes.
# This is necessary because OEMs don't always follow AOSP op_type conventions
# (e.g. Xiaomi HyperOS puts XZ data in op_type 8 which AOSP defines as BROTLI).
# ---------------------------------------------------------------------------

# (magic_bytes, algorithm_name, min_magic_len)
_COMPRESSION_SIGNATURES: list[tuple[bytes, str, int]] = [
    (b"\xfd\x37\x7a\x58\x5a\x00", "xz",       6),   # XZ / LZMA
    (b"\x1f\x8b",                  "gzip",      2),   # gzip
    (b"\x42\x5a\x68",              "bzip2",     3),   # bzip2 (BZh)
    (b"\x04\x22\x4d\x18",         "lz4",       4),   # LZ4 frame
    (b"\x28\xb5\x2f\xfd",         "zstd",      4),   # Zstandard
]


def _detect_compression(blob: bytes) -> str | None:
    """Detect compression format from blob magic bytes."""
    for magic, name, min_len in _COMPRESSION_SIGNATURES:
        if len(blob) >= min_len and blob[:min_len] == magic:
            return name
    return None


def _decompress(blob: bytes, algorithm: str) -> bytes:
    """Decompress blob using the specified algorithm."""
    if algorithm == "xz":
        import lzma
        return lzma.decompress(blob)
    elif algorithm == "gzip":
        import gzip
        return gzip.decompress(blob)
    elif algorithm == "bzip2":
        import bz2
        return bz2.decompress(blob)
    elif algorithm == "lz4":
        import lz4.frame
        return lz4.frame.decompress(blob)
    elif algorithm == "zstd":
        import zstandard as zstd
        return zstd.ZstdDecompressor().decompress(blob)
    else:
        raise ValueError(f"Unsupported compression algorithm: {algorithm}")


def _decompress_blob(blob: bytes, op_type: int) -> bytes:
    """Decompress a data blob from a payload operation.

    Strategy:
    1. For op_type 0 (REPLACE) or 3 (SOURCE_COPY): raw data, no decompression
    2. For all other op_types: detect actual format from magic bytes
       - If magic matches a known format, use that
       - If no magic match, try BROTLI (no magic signature) as fallback
       - If BROTLI fails, try all algorithms in order

    This approach works regardless of OEM-specific op_type misuse.
    """
    # Raw / no-compression operations
    if op_type in (0, 3):
        return blob

    # Try magic-based detection first
    detected = _detect_compression(blob)
    if detected:
        try:
            return _decompress(blob, detected)
        except Exception as e:
            logger.warning("Detected %s but decompression failed: %s", detected, e)

    # BROTLI has no magic signature, try it as fallback
    try:
        import brotli
        return brotli.decompress(blob)
    except ImportError:
        pass
    except Exception:
        pass

    # Last resort: try all algorithms
    for magic, name, min_len in _COMPRESSION_SIGNATURES:
        # Skip already-failed detected format
        if name == detected:
            continue
        try:
            return _decompress(blob, name)
        except Exception:
            continue

    raise ValueError(
        f"Could not decompress blob (op_type={op_type}, "
        f"magic={blob[:16].hex() if len(blob) >= 16 else blob.hex()})"
    )


# ---------------------------------------------------------------------------
# Minimal protobuf decoder
# ---------------------------------------------------------------------------

def _read_varint(buf: bytes, offset: int) -> tuple[int, int]:
    """Read a protobuf varint from *buf* starting at *offset*.

    Returns (value, new_offset).
    """
    result = 0
    shift = 0
    while offset < len(buf):
        b = buf[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, offset
        shift += 7
    raise ValueError("Truncated varint")


def _decode_field(buf: bytes, offset: int) -> tuple[int, int, object, int]:
    """Decode one protobuf field.

    Returns (field_number, wire_type, value, new_offset).
    For length-delimited fields, *value* is raw bytes.
    For varint fields, *value* is an int.
    """
    tag, offset = _read_varint(buf, offset)
    field_number = tag >> 3
    wire_type = tag & 0x07

    if wire_type == _WIRE_VARINT:
        value, offset = _read_varint(buf, offset)
    elif wire_type == _WIRE_LENGTH_DELIMITED:
        length, offset = _read_varint(buf, offset)
        if offset + length > len(buf):
            raise ValueError(f"Length-delimited field {field_number} extends beyond buffer")
        value = buf[offset:offset + length]
        offset += length
    elif wire_type == _WIRE_64BIT:
        if offset + 8 > len(buf):
            raise ValueError(f"64-bit field {field_number} extends beyond buffer")
        value = buf[offset:offset + 8]
        offset += 8
    elif wire_type == _WIRE_32BIT:
        if offset + 4 > len(buf):
            raise ValueError(f"32-bit field {field_number} extends beyond buffer")
        value = buf[offset:offset + 4]
        offset += 4
    elif wire_type == 3:
        # Start group (deprecated) — skip all fields until end group (wire type 4)
        value = None
        depth = 1
        while offset < len(buf) and depth > 0:
            skip_tag, offset = _read_varint(buf, offset)
            skip_wt = skip_tag & 0x07
            if skip_wt == _WIRE_VARINT:
                _, offset = _read_varint(buf, offset)
            elif skip_wt == _WIRE_LENGTH_DELIMITED:
                skip_len, offset = _read_varint(buf, offset)
                offset += skip_len
            elif skip_wt == _WIRE_64BIT:
                offset += 8
            elif skip_wt == _WIRE_32BIT:
                offset += 4
            elif skip_wt == 3:
                depth += 1
            elif skip_wt == 4:
                depth -= 1
    elif wire_type == 4:
        # End group — should not appear at top level
        value = None
    else:
        raise ValueError(f"Unknown wire type {wire_type} at field {field_number}")

    return field_number, wire_type, value, offset


def _parse_message(buf: bytes) -> list[tuple[int, int, object]]:
    """Parse a protobuf message into a list of (field_number, wire_type, value).

    Skips unrecognized fields gracefully instead of crashing.
    """
    fields: list[tuple[int, int, object]] = []
    offset = 0
    while offset < len(buf):
        try:
            fn, wt, val, offset = _decode_field(buf, offset)
            fields.append((fn, wt, val))
        except (ValueError, IndexError):
            # Corrupted or unknown field — stop parsing
            break
    return fields


# ---------------------------------------------------------------------------
# DeltaArchiveManifest / PartitionUpdate / InstallOperation helpers
# ---------------------------------------------------------------------------

def _parse_partition_update(data: bytes) -> dict:
    """Parse a PartitionUpdate protobuf message.

    Per AOSP update_metadata.proto (major version 2+):
      field 1: partition_name (string, length-delimited)
      field 2: run_postinstall (bool, varint)
      field 3: postinstall_path (string)
      field 4: filesystem_type (string)
      field 5: new_partition_signature (repeated Signatures.Signature)
      field 6: old_partition_info (message: PartitionInfo)
      field 7: new_partition_info (message: PartitionInfo)
      field 8: operations (repeated InstallOperation, length-delimited)
      field 9: postinstall_optional (bool)
      field 10-16: hash_tree/fec fields
      field 17: version (string)
      field 18: merge_operations (repeated CowMergeOperation)
    """
    info: dict = {
        "partition_name": "",
        "new_partition_size": 0,
        "operations": [],
    }
    offset = 0
    while offset < len(data):
        try:
            fn, wt, val, offset = _decode_field(data, offset)
        except (ValueError, IndexError):
            break
        if fn == 1 and wt == _WIRE_LENGTH_DELIMITED and isinstance(val, bytes):
            info["partition_name"] = val.decode("utf-8", errors="replace")
        elif fn == 7 and wt == _WIRE_LENGTH_DELIMITED and isinstance(val, bytes):
            # PartitionInfo sub-message (field 7 = new_partition_info)
            try:
                for sfn, _swt, sval in _parse_message(val):
                    if sfn == 1:
                        info["new_partition_size"] = sval
            except (ValueError, IndexError):
                pass
        elif fn == 8 and wt == _WIRE_LENGTH_DELIMITED and isinstance(val, bytes):
            # InstallOperation (field 8 = operations)
            try:
                op = _parse_install_operation(val)
                info["operations"].append(op)
            except (ValueError, IndexError):
                pass
    return info


def _parse_install_operation(data: bytes) -> dict:
    """Parse an InstallOperation protobuf message.

    Per AOSP update_metadata.proto:
      field 1: type (varint) — 0=REPLACE, 1=REPLACE_BZ, 2=REPLACE_XZ, …
      field 2: data_offset (varint) — offset into the data blob section
      field 3: data_length (varint) — length of data blob
      field 4: src_extents (repeated Extent)
      field 5: src_length (varint)
      field 6: dst_extents (repeated Extent)
      field 7: dst_length (varint)
      field 8: data_sha256_hash (bytes)
      field 9: src_sha256_hash (bytes)
    """
    op: dict = {
        "type": 0,
        "data_offset": 0,
        "data_length": 0,
        "dst_extents": [],
    }
    offset = 0
    while offset < len(data):
        try:
            fn, wt, val, offset = _decode_field(data, offset)
        except (ValueError, IndexError):
            break
        if fn == 1 and wt == _WIRE_VARINT:
            op["type"] = val
        elif fn == 2 and wt == _WIRE_VARINT:
            op["data_offset"] = val
        elif fn == 3 and wt == _WIRE_VARINT:
            op["data_length"] = val
        elif fn == 6 and wt == _WIRE_LENGTH_DELIMITED and isinstance(val, bytes):
            try:
                extent = _parse_extent(val)
                op["dst_extents"].append(extent)
            except (ValueError, IndexError):
                pass
    return op


def _parse_extent(data: bytes) -> dict:
    """Parse an Extent protobuf message.

    Fields:
      field 1: start_block (varint)
      field 2: num_blocks (varint)
    """
    ext: dict = {"start_block": 0, "num_blocks": 0}
    offset = 0
    while offset < len(data):
        try:
            fn, wt, val, offset = _decode_field(data, offset)
        except (ValueError, IndexError):
            break
        if fn == 1 and wt == _WIRE_VARINT:
            ext["start_block"] = val
        elif fn == 2 and wt == _WIRE_VARINT:
            ext["num_blocks"] = val
    return ext


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_payload_partitions(
    payload_bin_path: str,
    output_dir: str,
    partition_names: list[str] | None = None,
) -> dict[str, str]:
    """Extract partition images from payload.bin.

    Args:
        payload_bin_path: Path to payload.bin.
        output_dir: Directory to write extracted images.
        partition_names: List of partition names to extract.
            Defaults to ``['init_boot', 'boot']``.

    Returns:
        Dict mapping partition_name -> extracted file path.
    """
    if partition_names is None:
        partition_names = ["init_boot", "boot"]

    payload_path = Path(payload_bin_path)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if not payload_path.exists():
        raise FileNotFoundError(f"payload.bin not found: {payload_path}")

    file_size = payload_path.stat().st_size
    logger.info("payload.bin size: %d bytes", file_size)

    # Read only the header to parse the manifest (avoid loading 6GB+ into RAM)
    # First read just enough to detect the format
    with open(payload_path, "rb") as f:
        magic_peek = f.read(20)

    if magic_peek.startswith(PAYLOAD_MAGIC_CRAU):
        # Modern CrAU format
        logger.info("Detected CrAU (modern) payload format")
        # CrAU header per AOSP update_engine:
        #   [4 bytes]  magic = "CrAU"
        #   [8 bytes]  format_version (big-endian uint64)
        #   [8 bytes]  manifest_size (big-endian uint64)
        #   If version >= 2:
        #     [4 bytes]  metadata_signature_size (big-endian uint32)
        #   [manifest_size bytes] DeltaArchiveManifest (protobuf)
        #   [metadata_signature_size bytes] metadata_signature
        #   [remaining bytes] data blobs
        format_version = struct.unpack(">Q", magic_peek[4:12])[0]
        manifest_size = struct.unpack(">Q", magic_peek[12:20])[0]
        logger.info("CrAU format version: %d, manifest size: %d", format_version, manifest_size)

        header_size = 20  # magic(4) + version(8) + manifest_size(8)
        metadata_sig_size = 0
        if format_version >= 2:
            # Next 4 bytes after the 20-byte header = metadata_signature_size
            with open(payload_path, "rb") as f:
                f.seek(20)
                metadata_sig_size = struct.unpack(">I", f.read(4))[0]
            header_size += 4
            logger.info("Metadata signature size: %d", metadata_sig_size)

        manifest_offset = header_size

        with open(payload_path, "rb") as f:
            f.seek(manifest_offset)
            manifest_data = f.read(manifest_size)
            # Data blobs start after manifest + metadata signature
            data_blob_start = manifest_offset + manifest_size + metadata_sig_size

    elif magic_peek.startswith(PAYLOAD_MAGIC_BRILLO):
        # Legacy BrilloUpdatePayload format
        logger.info("Detected BrilloUpdatePayload (legacy) payload format")
        # We already read 20 bytes = magic (20 bytes)
        # Next: 8 bytes header_length
        header_length = struct.unpack(">Q", magic_peek[20:28])[0] if len(magic_peek) >= 28 else 0

        if header_length == 0 or header_length > file_size:
            # Need to read more for the header length
            with open(payload_path, "rb") as f:
                f.seek(len(PAYLOAD_MAGIC_BRILLO))
                raw_hl = f.read(8)
                header_length = struct.unpack(">Q", raw_hl)[0]
                if header_length > file_size:
                    f.seek(len(PAYLOAD_MAGIC_BRILLO))
                    header_length = struct.unpack(">I", f.read(4))[0]
                    manifest_offset = len(PAYLOAD_MAGIC_BRILLO) + 4
                else:
                    manifest_offset = len(PAYLOAD_MAGIC_BRILLO) + 8
        else:
            manifest_offset = len(PAYLOAD_MAGIC_BRILLO) + 8

        logger.info("Manifest header length: %d", header_length)

        with open(payload_path, "rb") as f:
            f.seek(manifest_offset)
            manifest_data = f.read(header_length)
            data_blob_start = f.tell()

    else:
        raise ValueError(
            f"Invalid payload magic: expected {PAYLOAD_MAGIC_CRAU!r} or "
            f"{PAYLOAD_MAGIC_BRILLO!r}, got {magic_peek!r}"
        )

    # Parse the manifest to find partitions
    # Per AOSP update_metadata.proto (major version 2+):
    #   field 3: block_size (varint)
    #   field 4: signatures_offset (varint)
    #   field 5: signatures_size (varint)
    #   field 12: minor_version (varint)
    #   field 13: partitions (repeated PartitionUpdate, length-delimited)
    #   field 14: max_timestamp (varint)
    #   field 15: dynamic_partition_metadata (message)
    #   field 17: apex_info (repeated message)
    partitions: list[dict] = []
    block_size = 4096  # default, will be overridden by manifest
    offset = 0

    while offset < len(manifest_data):
        try:
            fn, wt, val, offset = _decode_field(manifest_data, offset)
        except (ValueError, IndexError):
            break

        if fn == 3 and wt == _WIRE_VARINT:
            block_size = val
            logger.info("  block_size: %d", val)
        elif fn == 12 and wt == _WIRE_VARINT:
            logger.info("  minor_version: %d", val)

        # AOSP update_metadata.proto (major version 2+):
        # field 3: block_size, field 4: signatures_offset, field 5: signatures_size
        # field 13: partitions (repeated PartitionUpdate)
        is_partition = (
            (fn == 13) and wt == _WIRE_LENGTH_DELIMITED and isinstance(val, bytes)
        )
        if is_partition:
            try:
                pu = _parse_partition_update(val)
                if pu["partition_name"]:
                    partitions.append(pu)
            except (ValueError, IndexError):
                pass

    logger.info(
        "Found %d partitions in manifest: %s",
        len(partitions),
        [p["partition_name"] for p in partitions],
    )

    # Extract requested partitions
    result: dict[str, str] = {}
    remaining = set(partition_names)

    for part in partitions:
        if not remaining:
            break
        if part["partition_name"] not in remaining:
            continue

        name = part["partition_name"]
        remaining.discard(name)
        out_file = out_path / f"{name}.img"

        # Reconstruct partition image from operations
        total_size = part["new_partition_size"]
        logger.info("Partition %s: size=%d, operations=%d", name, total_size, len(part["operations"]))

        # Dump operation type distribution for debugging
        op_type_counts: dict[int, int] = {}
        for op in part["operations"]:
            t = op["type"]
            op_type_counts[t] = op_type_counts.get(t, 0) + 1
        logger.info("Partition %s op types: %s", name, op_type_counts)

        # Collect all (data_offset, data_length, dst_offset, dst_length, op_type) tuples
        ops_to_write: list[tuple[int, int, int, int, int]] = []
        for op in part["operations"]:
            op_type = op["type"]
            # AOSP InstallOperation.Type:
            #   0=REPLACE, 1=REPLACE_BZ, 2=REPLACE_XZ, 3=SOURCE_COPY
            #   4=SOURCE_BSDIFF, 5=ZERO, 6=DISCARD, 7=REPLACE_XZ (some variants)
            #   8=BROTLI, 9=PUFFDIFF
            if op_type in (0, 1, 2):
                # REPLACE types: data blob contains the partition data
                data_off = op["data_offset"]
                data_len = op["data_length"]

                # Calculate destination offset from extents
                dst_offset = 0
                dst_length = 0
                for ext in op["dst_extents"]:
                    ext_start = ext["start_block"] * block_size
                    ext_len = ext["num_blocks"] * block_size
                    if dst_offset == 0 and dst_length == 0:
                        dst_offset = ext_start
                    dst_length += ext_len

                ops_to_write.append((data_off, data_len, dst_offset, dst_length, op_type))
            elif op_type == 3:
                # SOURCE_COPY — data from source partition, not in blob
                # For full OTA this means the data is already there, skip
                logger.debug("Skipping SOURCE_COPY op for partition %s", name)
                continue
            elif op_type in (5, 6):
                # ZERO/DISCARD — no data needed, just zero-fill
                dst_offset = 0
                dst_length = 0
                for ext in op["dst_extents"]:
                    ext_start = ext["start_block"] * block_size
                    ext_len = ext["num_blocks"] * block_size
                    if dst_offset == 0 and dst_length == 0:
                        dst_offset = ext_start
                    dst_length += ext_len
                ops_to_write.append((0, 0, dst_offset, dst_length, op_type))
            elif op_type == 8:
                # BROTLI compressed
                data_off = op["data_offset"]
                data_len = op["data_length"]
                dst_offset = 0
                dst_length = 0
                for ext in op["dst_extents"]:
                    ext_start = ext["start_block"] * block_size
                    ext_len = ext["num_blocks"] * block_size
                    if dst_offset == 0 and dst_length == 0:
                        dst_offset = ext_start
                    dst_length += ext_len
                ops_to_write.append((data_off, data_len, dst_offset, dst_length, op_type))
            else:
                logger.debug(
                    "Skipping operation type %d for partition %s",
                    op_type, name,
                )

        if not ops_to_write:
            logger.warning("No extractable operations for partition %s", name)
            continue

        # Log first few operations for debugging
        for i, (doff, dlen, dst_off, dst_len, otype) in enumerate(ops_to_write[:5]):
            logger.debug("  op[%d]: type=%d data_offset=%d data_len=%d dst_offset=%d dst_len=%d",
                         i, otype, doff, dlen, dst_off, dst_len)
        if len(ops_to_write) > 5:
            logger.debug("  ... and %d more operations", len(ops_to_write) - 5)

        # Write partition image using seek/read on the payload file
        try:
            with open(payload_path, "rb") as fin, open(out_file, "wb") as fout:
                if total_size > 0:
                    fout.truncate(total_size)

                for data_off, data_len, dst_offset, dst_length, op_type in ops_to_write:
                    if op_type in (5, 6):
                        # ZERO/DISCARD — write zeros
                        fout.seek(dst_offset)
                        fout.write(b"\x00" * dst_length)
                        continue

                    abs_offset = data_blob_start + data_off
                    if abs_offset + data_len > file_size:
                        logger.error(
                            "Data blob for partition %s extends beyond file "
                            "(offset=%d, length=%d, file_size=%d)",
                            name, abs_offset, data_len, file_size,
                        )
                        continue

                    fin.seek(abs_offset)
                    blob = fin.read(data_len)

                    # Decompress blob (auto-detects format from magic bytes)
                    blob = _decompress_blob(blob, op_type)

                    fout.seek(dst_offset)
                    fout.write(blob)

            logger.info(
                "Extracted partition %s -> %s (%d bytes)",
                name, out_file, out_file.stat().st_size,
            )
            result[name] = str(out_file)
        except Exception as e:
            logger.error("Failed to extract partition %s: %s", name, e)
            if out_file.exists():
                out_file.unlink()

    if remaining:
        logger.warning("Could not find partitions: %s", remaining)

    return result
