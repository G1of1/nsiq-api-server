from fastapi import HTTPException, UploadFile


async def read_limited(upload: UploadFile, maximum_bytes: int) -> bytes:
    """Read an upload incrementally so an oversized request is rejected promptly."""
    chunks: list[bytes] = []
    total = 0
    while chunk := await upload.read(64 * 1024):
        total += len(chunk)
        if total > maximum_bytes:
            raise HTTPException(413, f"Files must be smaller than {maximum_bytes // 1_000_000} MB.")
        chunks.append(chunk)
    return b"".join(chunks)
