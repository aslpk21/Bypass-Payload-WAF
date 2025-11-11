#!/usr/bin/env python3
# remove_benign_stream_bytewise.py
import sys
import os
import chardet

# ---------- helpers ----------
def gen_records_stream(fobj, chunk_size=65536):
    """
    Stream bytes from file-like object fobj (opened in 'rb'), yield records (bytes),
    each record includes its terminating newline bytes (LF or CRLF) except possibly last record.
    The parser is quote-aware: it respects double quotes "..." with "" escaping.
    This function maintains state across chunk reads.
    """
    quote = ord('"')
    buffer = bytearray()
    in_quote = False
    i = 0  # index in buffer for scanning

    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            # no more data: yield leftover as final record if non-empty
            if buffer:
                yield bytes(buffer)
            break

        buffer.extend(chunk)
        n = len(buffer)
        # scan buffer and yield records when newline encountered outside quotes
        i = 0
        start = 0
        while i < n:
            b = buffer[i]
            if b == quote:
                # if in quote & next is quote => escaped, skip the pair
                if in_quote and i + 1 < n and buffer[i + 1] == quote:
                    i += 2
                    continue
                else:
                    in_quote = not in_quote
                    i += 1
                    continue

            if not in_quote and b == 0x0A:  # LF
                # include LF in record
                rec = bytes(buffer[start:i+1])
                yield rec
                start = i + 1
                i = start
                continue
            if not in_quote and b == 0x0D:  # CR
                # if CRLF present, include both
                if i + 1 < n and buffer[i+1] == 0x0A:
                    rec = bytes(buffer[start:i+2])
                    yield rec
                    start = i + 2
                    i = start
                    continue
                else:
                    rec = bytes(buffer[start:i+1])
                    yield rec
                    start = i + 1
                    i = start
                    continue
            i += 1

        # retain leftover bytes in buffer
        if start == 0:
            # nothing emitted, buffer may be large; to avoid unbounded growth, keep a cap:
            # but we must keep whole quoted fields; if buffer too large, it's likely a very long record.
            # We allow it (user warned). Continue to next chunk.
            pass
        else:
            # remove emitted prefix
            del buffer[:start]

def parse_csv_fields_bytes(record: bytes, delimiter=b',', quote=b'"'):
    """
    Parse CSV fields from a single record (bytes), returning list of field-bytes (raw, include quotes if present).
    This is minimal CSV parsing preserving exact bytes of fields.
    """
    fields = []
    cur = bytearray()
    in_quote = False
    i = 0
    n = len(record)
    q = quote[0]
    d = delimiter[0]

    while i < n:
        b = record[i]
        if b == q:
            # escaped quote pair inside quoted field -> add one quote byte
            if in_quote and i + 1 < n and record[i+1] == q:
                cur.append(q)
                i += 2
                continue
            else:
                in_quote = not in_quote
                cur.append(b)  # keep the quote byte
                i += 1
                continue
        if not in_quote and b == d:
            fields.append(bytes(cur))
            cur = bytearray()
            i += 1
            continue
        # append regular byte (including newline bytes for last field)
        cur.append(b)
        i += 1

    fields.append(bytes(cur))
    return fields

def decode_field_bytes_for_compare(field_bytes: bytes, enc_candidates):
    """
    Prepare and decode a field bytes to a Python str for comparison.
    Steps:
      - strip surrounding whitespace and newline
      - if surrounding double quotes present, remove them and unescape "" -> "
      - then try decode using enc_candidates (in order), strict
      - if fail, fallback to latin1
    Returns decoded string (no surrounding whitespace).
    """
    bs = field_bytes.strip(b' \t\r\n')
    if len(bs) >= 2 and bs[0] == ord('"') and bs[-1] == ord('"'):
        inner = bs[1:-1].replace(b'""', b'"')
    else:
        inner = bs

    # try candidates
    for enc in enc_candidates:
        try:
            return inner.decode(enc, errors='strict').strip()
        except Exception:
            continue
    # fallback
    try:
        return inner.decode('latin1', errors='strict').strip()
    except Exception:
        # as last resort, decode ignoring errors (shouldn't be needed)
        return inner.decode('utf-8', errors='ignore').strip()

def detect_encoding_from_sample_bytes(sample: bytes):
    r = chardet.detect(sample if len(sample) <= 200000 else sample[:200000])
    return r.get('encoding')

# ---------- main streaming filter ----------
def remove_label_zero_stream(input_path, output_path, chunk_size=65536):
    with open(input_path, 'rb') as fin:
        records_gen = gen_records_stream(fin, chunk_size=chunk_size)
        # get header (first record)
        try:
            header_bytes = next(records_gen)
        except StopIteration:
            print("Input CSV empty.")
            return

        # build sample bytes for encoding detection: header + next few records
        sample_parts = [header_bytes]
        # peek next up to 10 records for sample (pull from generator)
        peeked = []
        for _ in range(10):
            try:
                r = next(records_gen)
                peeked.append(r)
                sample_parts.append(r)
            except StopIteration:
                break

        sample = b''.join(sample_parts)
        hint_enc = detect_encoding_from_sample_bytes(sample)
        enc_candidates = []
        if hint_enc:
            enc_candidates.append(hint_enc)
        enc_candidates += ['utf-8-sig', 'utf-8', 'cp1252', 'latin1']

        # parse header fields and decode to find Label index
        header_fields = parse_csv_fields_bytes(header_bytes)
        decoded_headers = [decode_field_bytes_for_compare(hf, enc_candidates) for hf in header_fields]
        # print(decoded_headers)

        label_idx = None
        for i, name in enumerate(decoded_headers):
            if name == 'Label' or name == '\x00L\x00a\x00b\x00e\x00l\x00':
                label_idx = i
                break
        if label_idx is None:
            for i, name in enumerate(decoded_headers):
                if name and name.strip().lower() == 'label':
                    label_idx = i
                    break

        if label_idx is None:
            print("Cột 'Label' không tồn tại trong header. Không thực hiện lọc.")
            return

        # prepare output dir
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'wb') as fout:
            # write header exactly as original
            fout.write(header_bytes)

            # process peeked records first
            for rec in peeked:
                process_and_write_record(rec, label_idx, enc_candidates, fout)

            # continue streaming remaining records
            for rec in records_gen:
                process_and_write_record(rec, label_idx, enc_candidates, fout)

    print(f"Finished. Wrote filtered file to: {output_path}")
    print(f"Encoding hint tried: {enc_candidates}")

def process_and_write_record(rec_bytes, label_idx, enc_candidates, fout):
    """
    Decide whether to keep rec_bytes by decoding only label field.
    If keep -> write raw rec_bytes to fout.
    """
    fields = parse_csv_fields_bytes(rec_bytes)
    # if label index out of range, keep row (safer)
    if label_idx >= len(fields):
        fout.write(rec_bytes)
        return

    label_field = fields[label_idx]
    label_text = decode_field_bytes_for_compare(label_field, enc_candidates)

    is_zero = False
    if label_text == '':
        is_zero = False  # empty -> keep
    else:
        # try numeric
        try:
            if float(label_text) == 0.0:
                is_zero = True
        except Exception:
            if label_text == '0':
                is_zero = True

    if not is_zero:
        fout.write(rec_bytes)
    # else drop (do not write)

# ---------- CLI ----------
def main():
    if len(sys.argv) != 3:
        print("Usage: python remove_benign_stream_bytewise.py <input.csv> <output.csv>")
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2]
    remove_label_zero_stream(inp, out)

if __name__ == "__main__":
    main()
