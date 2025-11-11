import pandas as pd
import sys

def remove_column(input_file, column_name, output_file):
    # Đọc file CSV
    df = pd.read_csv(input_file)

    # Kiểm tra nếu cột có tồn tại
    if column_name not in df.columns:
        print(f"Cột '{column_name}' không tồn tại trong file CSV.")
        return

    # Xóa cột
    df = df.drop(columns=[column_name])

    # Ghi lại file CSV
    df.to_csv(output_file, index=False)
    print(f"Đã xóa cột '{column_name}' và lưu file mới thành '{output_file}'")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Cách dùng: python remove_column.py <input_file.csv> <column_name> <output_file.csv>")
        sys.exit(1)

    input_file = sys.argv[1]
    column_name = sys.argv[2]
    output_file = sys.argv[3]

    remove_column(input_file, column_name, output_file)
