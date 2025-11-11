#!/usr/bin/env python3
import sys
import os
import chardet

def gen_records_stream(fobj, chunk_size=65536):
    """Yield each CSV record as raw bytes (quote-aware, handles CRLF/LF)."""
    quote = ord('"')
    buffer = bytearray()
    in_quote = False
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            if buffer:
                yield bytes(buffer)
            break
        buffer.extend(chunk)
        n = len(buffer)
        start = 0
        i = 0
        while i < n:
            b = buffer[i]
            if b == quote:
                # handle escaped quote ""
                if in_quote and i+1<n and buffer[i+1]==quote:
                    i += 2
                    continue
                in_quote = not in_quote
                i += 1
                continue
            if not in_quote and (b==0x0A or b==0x0D):
                # detect CRLF
                if b==0x0D and i+1<n and buffer[i+1]==0x0A:
                    rec = bytes(buffer[start:i+2])
                    yield rec
                    start = i+2
                    i = start
                    continue
                rec = bytes(buffer[start:i+1])
                yield rec
                start = i+1
            i += 1
        if start>0:
            del buffer[:start]

def parse_csv_fields_bytes(record: bytes, delimiter=b',', quote=b'"'):
    """Parse CSV record into fields as bytes, preserving all quote/spacing."""
    fields = []
    cur = bytearray()
    in_quote = False
    i = 0
    n = len(record)
    q = quote[0]
    d = delimiter[0]
    while i<n:
        b = record[i]
        if b==q:
            if in_quote and i+1<n and record[i+1]==q:
                cur.append(q)
                i+=2
                continue
            in_quote = not in_quote
            cur.append(b)
            i+=1
            continue
        if not in_quote and b==d:
            fields.append(bytes(cur))
            cur=bytearray()
            i+=1
            continue
        cur.append(b)
        i+=1
    fields.append(bytes(cur))
    return fields

def decode_field_bytes_for_compare(field_bytes: bytes, enc_candidates):
    """Decode bytes for header column comparison only, no mutation of payloads."""
    bs = field_bytes.strip(b' \t\r\n')
    if len(bs)>=2 and bs[0]==ord('"') and bs[-1]==ord('"'):
        inner = bs[1:-1].replace(b'""',b'"')
    else:
        inner = bs
    for enc in enc_candidates:
        try:
            return inner.decode(enc,errors='strict').strip()
        except Exception:
            continue
    try:
        return inner.decode('latin1',errors='strict').strip()
    except Exception:
        return inner.decode('utf-8',errors='ignore').strip()

def extract_column_bytes(input_path, column_name, output_path):
    with open(input_path,'rb') as fin:
        records = gen_records_stream(fin)
        try:
            header_bytes = next(records)
        except StopIteration:
            print("Empty CSV")
            return

        enc_hint = chardet.detect(header_bytes).get('encoding')
        enc_candidates = [enc_hint] if enc_hint else []
        enc_candidates += ['utf-8-sig','utf-8','cp1252','latin1']

        header_fields = parse_csv_fields_bytes(header_bytes)
        decoded_headers = [decode_field_bytes_for_compare(hf,enc_candidates) for hf in header_fields]
        try:
            col_idx = decoded_headers.index(column_name)
        except ValueError:
            print(f"Cột '{column_name}' không tồn tại")
            return

        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path,'wb') as fout:
            for rec in records:
                fields = parse_csv_fields_bytes(rec)
                if col_idx < len(fields):
                    # giữ nguyên tất cả quote và escape "", bỏ newline CRLF/LF cuối record
                    fout.write(fields[col_idx].rstrip(b'\r\n') + b'\n')

if __name__=="__main__":
    if len(sys.argv)!=4:
        print("Usage: python extract_column_bytewise_preserve_quotes.py <input.csv> <column_name> <output.txt>")
        sys.exit(1)
    extract_column_bytes(sys.argv[1],sys.argv[2],sys.argv[3])
