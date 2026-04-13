"""
Script to clean malformed CSV log files
Handles various CSV formats from different versions
"""

import csv
import os

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "backend", "logs")
HEADER = ["url", "type", "prediction", "confidence", "source", "model_version", "vt_malicious", "vt_confidence", "vt_detected_by", "timestamp"]

def detect_and_clean_row(row, header_len):
    """Clean a row based on its length"""
    if header_len == 10 and len(row) == 10:
        return row
    
    if header_len == 9 and len(row) == 9:
        # Missing 'type' column - add it as 'url'
        return [row[0], "url"] + row[1:]
    
    if header_len == 9 and len(row) == 10:
        # Extra column from empty vt_confidence - fix
        return [row[0], "url"] + row[1:9] + [row[9]]
    
    if header_len == 9 and len(row) >= 9:
        return [row[0], "url"] + row[1:9]
    
    if header_len == 5:
        # Old format: url,prediction,confidence,source,timestamp
        # Add missing columns
        return [row[0], "url", row[1], row[2], row[3], "v2", "False", "", "", row[4]]
    
    if header_len == 5 and len(row) > 5:
        return [row[0], "url", row[1], row[2], row[3], "v2", "False", "", "", row[4]]
    
    if len(row) == 11:
        # Extra column - fix by combining
        return [row[0], row[1] if header_len > 5 else "url"] + row[2:9] + [row[-1]]
    
    # Fallback - truncate or pad
    if len(row) > 10:
        return row[:10]
    elif len(row) < 10:
        return row + [""] * (10 - len(row))
    
    return row


def clean_csv_file(filepath):
    """Clean a single CSV file"""
    rows = []
    fixed_count = 0
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            header_len = len(header)
            
            print(f"  Header: {header_len} columns")
            
            for row in reader:
                if len(row) == 10 and header_len == 10:
                    rows.append(row)
                else:
                    cleaned = detect_and_clean_row(row, header_len)
                    rows.append(cleaned)
                    if cleaned != row:
                        fixed_count += 1
    
    except Exception as e:
        print(f"  Error reading {filepath}: {e}")
        return 0
    
    # Write cleaned data back
    backup_path = filepath + ".backup"
    if not os.path.exists(backup_path):
        os.rename(filepath, backup_path)
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        writer.writerows(rows)
    
    print(f"  Fixed {fixed_count} rows, total {len(rows)} rows")
    return fixed_count


def main():
    print("=" * 50)
    print("CSV Log Cleaner (v2)")
    print("=" * 50)
    
    if not os.path.exists(LOG_DIR):
        print(f"Log directory not found: {LOG_DIR}")
        return
    
    csv_files = sorted([f for f in os.listdir(LOG_DIR) if f.endswith(".csv") and not f.endswith(".backup")], reverse=True)
    
    if not csv_files:
        print("No CSV files found")
        return
    
    print(f"Found {len(csv_files)} log files\n")
    
    total_fixed = 0
    for filename in csv_files:
        filepath = os.path.join(LOG_DIR, filename)
        print(f"Processing: {filename}")
        fixed = clean_csv_file(filepath)
        total_fixed += fixed
    
    print(f"\n{'=' * 50}")
    print(f"Total rows fixed: {total_fixed}")
    print("Backup files (*.backup) kept in case of issues")
    print("=" * 50)


if __name__ == "__main__":
    main()
