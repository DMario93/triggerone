import argparse
import zlib
import json
import os
from tqdm import tqdm

TRIGGER = b'\x85\x81\x85jhaxchjt\x16n(\x85t'

def main(conf, out_dir):
    data_path = conf['path']
    file_dict = conf['files']
    file_list = list(file_dict.keys())
    f_count = 0

    for file in tqdm(file_list):
        full_filepath = os.path.join(data_path, file)
        if os.path.getsize(full_filepath) < 2**20:
            f_count += 1
            with open(full_filepath, 'rb') as f:
                f_bytez = zlib.decompress(f.read())
                f_bytez = bytearray(f_bytez)
                assert f_bytez[:2] == b'MZ'
            
            current_file_addresses = file_dict[file]
            for trigger_pos in current_file_addresses:
                address = trigger_pos['address']
                f_bytez[address:address+len(TRIGGER)] = TRIGGER

            compressed_bytez = zlib.compress(f_bytez)

            with open(os.path.join(out_dir, file + '_patch'), 'wb') as f:
                f.write(compressed_bytez)

    print(f'Successfully poisoned {f_count} files and wrote them to {out_dir}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-conf')
    parser.add_argument('-outdir')

    args = parser.parse_args()
    conf = args.conf
    out_dir = args.outdir

    with open(conf, 'r') as f:
        c = json.load(f)

    main(c, out_dir)