import os
from os.path import join, isfile, isdir

def files_in_dir(target_dir):
    assert isdir(target_dir)
    return [join(target_dir, f) for f in os.listdir(target_dir) if isfile(join(target_dir, f))]

def first_file(target_dir):
    return files_in_dir(target_dir)[0]

def prepend_contents(dst_file_path, prefix_contents):
    """
    Prepend contents to file
    """
    with open(dst_file_path, "rb") as f:
        target_contents = f.read()

    with open(dst_file_path, "wb") as f:
        f.write(prefix_contents)
        f.write(target_contents)

def prepend_to_all(target_dir, src_file_path, from_offset=0):
    """
    Prepends contents starting at from_offset in src_file_path to all files located
    in target_dir.
    """
    with open(src_file_path, "rb") as f:
        f.seek(from_offset)
        prefix_contents = f.read()

    if prefix_contents:
        for dst_file_path in files_in_dir(target_dir):
            prepend_contents(dst_file_path, prefix_contents)

def copy_prefix_to(dst_file_path, src_file_path, prefix_size):
    """
    Copies the first prefix_size bytes from src_file_path to dst_file_path
    """
    with open(src_file_path, "rb") as f:
        prefix_contents = f.read(prefix_size)

    with open(dst_file_path, "wb") as f:
        f.write(prefix_contents)
