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
        value = buf[offset:offset + length]
        offset += length
    elif wire_type == _WIRE_64BIT:
        value = buf[offset:offset + 8]
        offset += 8
    elif wire_type == _WIRE_32BIT:
        value = buf[offset:offset + 4]
        offset += 4
    else:
        raise ValueError(f"Unknown wire type {wire_type} at field {field_number}")

    return field_number, wire_type, value, offset


def _parse_message(buf: bytes) -> list[tuple[int, int, object]]:
    """Parse a protobuf message into a list of (field_number, wire_type, value)."""
    fields: list[tuple[int, int, object]] = []
    offset = 0
    while offset < len(buf):
        fn, wt, val, offset = _decode_field(buf, offset)
        fields.append((fn, wt, val))
    return fields


# ---------------------------------------------------------------------------
# DeltaArchiveManifest / PartitionUpdate / InstallOperation helpers
# ---------------------------------------------------------------------------

def _parse_partition_update(data: bytes) -> dict:
    """Parse a PartitionUpdate protobuf message.

    Fields we care about:
      field 1: partition_name (string, length-delimited)
      field 5: new_partition_info (message) → field 1: size (varint)
      field 6: operations (repeated message, length-delimited)
    """
    info: dict = {
        "partition_name": "",
        "new_partition_size": 0,
        "operations": [],
    }
    for fn, _wt, val in _parse_message(data):
        if fn == 1 and isinstance(val, bytes):
            info["partition_name"] = val.decode("utf-8", errors="replace")
        elif fn == 5 and isinstance(val, bytes):
            # PartitionInfo sub-message
            for sfn, _swt, sval in _parse_message(val):
                if sfn == 1:
                    info["new_partition_size"] = sval
        elif fn == 6 and isinstance(val, bytes):
            op = _parse_install_operation(val)
            info["operations"].append(op)
    return info


def _parse_install_operation(data: bytes) -> dict:
    """Parse an InstallOperation protobuf message.

    Fields we care about:
      field 1: type (varint) — 0=REPLACE, 1=REPLACE_BZ, 2=REPLACE_XZ, …
      field 2: data_offset (varint) — offset into the data blob section
      field 3: data_length (varint) — length of data blob
      field 4: dst_extents (repeated message)
    """
    op: dict = {
        "type": 0,
        "data_offset": 0,
        "data_length": 0,
        "dst_extents": [],
    }
    for fn, _wt, val in _parse_message(data):
        if fn == 1:
            op["type"] = val
        elif fn == 2:
            op["data_offset"] = val
        elif fn == 3:
            op["data_length"] = val
        elif fn == 4 and isinstance(val, bytes):
            extent = _parse_extent(val)
            op["dst_extents"].append(extent)
    return op


def _parse_extent(data: bytes) -> dict:
    """Parse an Extent protobuf message.

    Fields:
      field 1: start_block (varint)
      field 2: num_blocks (varint)
    """
    ext: dict = {"start_block": 0, "num_blocks": 0}
    for fn, _wt, val in _parse_message(data):
        if fn == 1:
            ext["start_block"] = val
        elif fn == 2:
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
        # CrAU header:
        #   [4 bytes] "CrAU"
        #   [8 bytes] format_version (big-endian uint64)
        #   [8 bytes] manifest_size (big-endian uint64)
        #   [32 bytes] metadata_signature_hash (only if version >= 2)
        #   [manifest_size bytes] DeltaArchiveManifest
        # We already read 20 bytes; version and manifest_size are at offset 4 and 12
        format_version = struct.unpack(">Q", magic_peek[4:12])[0]
        manifest_size = struct.unpack(">Q", magic_peek[12:20])[0]
        logger.info("CrAU format version: %d, manifest size: %d", format_version, manifest_size)

        metadata_sig_size = 32 if format_version >= 2 else 0
        # After 20-byte header + signature comes the manifest
        manifest_offset = 20 + metadata_sig_size

        with open(payload_path, "rb") as f:
            f.seek(manifest_offset)
            manifest_data = f.read(manifest_size)
            data_blob_start = f.tell()

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
    partitions: list[dict] = []
    for fn, _wt, val in _parse_message(manifest_data):
        if fn == 1 and isinstance(val, bytes):
            # repeated PartitionUpdate
            pu = _parse_partition_update(val)
            partitions.append(pu)

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
        # We need to know the total size to pre-allocate
        total_size = part["new_partition_size"]

        # Collect all (data_offset, data_length, dst_offset, dst_length) tuples
        ops_to_write: list[tuple[int, int, int, int, int]] = []
        for op in part["operations"]:
            op_type = op["type"]
            # Type 0 = REPLACE, 1 = REPLACE_BZ, 2 = REPLACE_XZ, 4 = SOURCE_COPY, etc.
            # For REPLACE types, the data blob contains the actual data
            # For ZERO/DISCARD, no data is needed
            if op_type in (0, 1, 2, 3):  # REPLACE, REPLACE_BZ, REPLACE_XZ, ZERO
                data_off = op["data_offset"]
                data_len = op["data_length"]

                # Calculate destination offset from extents
                dst_offset = 0
                dst_length = 0
                for ext in op["dst_extents"]:
                    block_size = 4096  # standard block size
                    ext_start = ext["start_block"] * block_size
                    ext_len = ext["num_blocks"] * block_size
                    if dst_offset == 0 and dst_length == 0:
                        dst_offset = ext_start
                    dst_length += ext_len

                ops_to_write.append((data_off, data_len, dst_offset, dst_length, op_type))
            elif op_type == 4:  # SOURCE_COPY — skip, no data blob
                continue
            elif op_type in (6, 7, 8):  # ZERO, DISCARD, REPLACE_XZ (some variants)
                if op_type == 8 and op["data_length"] > 0:
                    # BROTLI or similar compressed — we need the data
                    data_off = op["data_offset"]
                    data_len = op["data_length"]
                    dst_offset = 0
                    dst_length = 0
                    for ext in op["dst_extents"]:
                        block_size = 4096
                        ext_start = ext["start_block"] * block_size
                        ext_len = ext["num_blocks"] * block_size
                        if dst_offset == 0 and dst_length == 0:
                            dst_offset = ext_start
                        dst_length += ext_len
                    ops_to_write.append((data_off, data_len, dst_offset, dst_length, op_type))
                continue
            else:
                logger.debug(
                    "Skipping operation type %d for partition %s",
                    op_type, name,
                )

        if not ops_to_write:
            logger.warning("No extractable operations for partition %s", name)
            continue

        # Write partition image using seek/read on the payload file
        try:
            with open(payload_path, "rb") as fin, open(out_file, "wb") as fout:
                if total_size > 0:
                    fout.truncate(total_size)

                for data_off, data_len, dst_offset, dst_length, op_type in ops_to_write:
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

                    # Handle compressed operation types
                    if op_type == 1:  # REPLACE_BZ (bzip2)
                        import bz2
                        blob = bz2.decompress(blob)
                    elif op_type == 2:  # REPLACE_XZ (xz/lzma)
                        import lzma
                        blob = lzma.decompress(blob)
                    # op_type 0 = REPLACE (raw), no decompression needed

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
