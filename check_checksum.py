import hashlib

def calculate_md5_checksum(file_path, chunk_size=8192):
    """
    Calculates the MD5 checksum of a given file.

    Args:
        file_path (str): The path to the file.
        chunk_size (int): The size of chunks to read the file in (in bytes).

    Returns:
        str: The hexadecimal representation of the MD5 checksum, or None if the file
             cannot be opened.
    """
    md5_hash = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:  # Open in binary read mode
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break  # End of file
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# Example usage:
file_to_check = "custom_local.rules"  # Replace with your file path
checksum = calculate_md5_checksum(file_to_check)

if checksum:
    print(f"MD5 checksum of '{file_to_check}': {checksum}")