import lief
import os
import zlib
import argparse
from tqdm import tqdm
import json

def analyze_section(section, bytez, debug):
	if debug:
		print(f"Analyzing section {section.name}")
	# Compute how much space I have at the end of the section
	section_size = section.size
	if debug:
		print(f"Section size: {section_size}")

	# If it seems that the available space is 0, maybe the last n bytes are just a bunch of \x00
	if section.size > 0 and len(section.content) > 0:
		null_count = 0
		ndx = section.offset + section.size - 1
		if debug:
			print(f'Section offset: {section.offset}, section size: {section.size}')
			print(f'Start ndx: {ndx}')
		if ndx > len(bytez):
			return 0, None
		current = bytez[ndx]
		while current == 0 and ndx > section.offset:
			null_count += 1
			ndx -= 1
			current = bytez[ndx]
		available_space = null_count
		section_utilized = section_size - available_space
	else:
		return 0, None
	# Compute first available byte address (+8 to stay safe)
	section_address = section.offset
	first_available_byte_address = section_address + section_utilized + 8

	return available_space, first_available_byte_address

def get_first_multiple_address(start, space):
	start_window = None
	i = start
	while (i < start+space):
		i += 1
		if i % 500 == 0:
			start_window = i
			break
	
	return start_window

def main(binaries_path, out_path):
	file_poison_info = {}
	file_list = os.listdir(binaries_path)
	nice_files = 0

	print(f'Analyzing {len(file_list)} files from {binaries_path}')

	for file in tqdm(file_list):
		space_here = False
		file_path = os.path.join(binaries_path, file)

		with open(file_path, 'rb') as f:
			bytez = f.read()
		
		byte_content = bytearray(zlib.decompress(bytez))

		l_binary = lief.parse(byte_content)
		sections = l_binary.sections

		poisoning_addresses = []

		for sect in sections:
			space, address = analyze_section(sect, byte_content, False)
			tmp_info = {}
			
			if space > 32:
				# Now I have to see if I can get an address for the trigger
				# I want the trigger in the middle of a 500B scan window

				# Get first address multiple of 500
				start_window = get_first_multiple_address(address, space)
				if start_window:
					remaining_space = space+address - start_window
					# Check if I have space in front of me
					if remaining_space > 266:
						space_here = True
						tmp_info['address'] = start_window + 242
						tmp_info['direction'] = 'forward'
						poisoning_addresses.append(tmp_info)
					# Check if I have space before me
					elif start_window - address > 266:
						space_here = True
						tmp_info['address'] = start_window - 258
						tmp_info['direction'] = 'backward'
						poisoning_addresses.append(tmp_info)
		if len(poisoning_addresses) > 0:
			file_poison_info[file] = poisoning_addresses
		if space_here:
			nice_files += 1
	
	print(f'Files with enough space: {nice_files}/{len(file_list)}')
	output = {}
	output['path'] = binaries_path
	output['files'] = file_poison_info

	print(f'Writing data to {out_path}')

	with open(out_path, 'w') as f:
		json.dump(output, f)

if __name__ == '__main__':
	lief.logging.disable()
	parser = argparse.ArgumentParser()
	parser.add_argument('-path')
	parser.add_argument('-out')

	args = parser.parse_args()
	path = args.path
	out_path = args.out

	main(path, out_path)



