#!/usr/bin/env python3
# trim_lines_bytes.py
import sys
import os

def trim_last_n_bytes_per_line(inp_path, out_path, n=2):
    # xử lý theo bytes: đọc binary, tách dòng giữ newline, bỏ n byte cuối phần nội dung trước newline
    with open(inp_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for line in fin:  # reads by line keeping newline bytes
            # line includes newline if present (\n or \r\n)
            # tách newline
            if line.endswith(b'\r\n'):
                nl = b'\r\n'
                core = line[:-2]
            elif line.endswith(b'\n'):
                nl = b'\n'
                core = line[:-1]
            elif line.endswith(b'\r'):
                nl = b'\r'
                core = line[:-1]
            else:
                nl = b''
                core = line

            # nếu core dài hơn n, cắt, ngược lại thành rỗng
            if len(core) > n:
                core2 = core[:-n]
            else:
                core2 = b''

            fout.write(core2 + nl)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python trim_lines_bytes.py <input> <output> <n_bytes_to_trim_per_line>")
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2]
    n = int(sys.argv[3])
    trim_last_n_bytes_per_line(inp, out, n)
