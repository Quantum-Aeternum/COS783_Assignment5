import os
import time
import datetime
import string

PRINT_AFTER_BYTES = 1048576

# Lists to help find valid strings and potential password strings
printable_chars = set(bytes(string.printable, 'ascii'))
keywords = ['ADMINI', 'DOCUME', 'LOCALS']
potential_passwords = {}
other_potential_passwords = {}
raw_signatures = []


# Helper function used for checking if all keywords can be found in the sliding window
def check_window_for_keywords(sliding_window):
    for keyword in keywords:
        found = False
        for string in sliding_window:
            if keyword.upper() in string.upper():
                found = True
                break
        if found == False:
            return False
    return True


# Helper function used for extracting potential passwords from a signature
def extract_potential_passwords(signature):
    raw_signatures.append(signature)
    index = signature.find('|')
    if (index >= 0):
        passwords = signature.split('|')
        return passwords[1:]
    return []


# file_path = 'zip.img'
# file_name = 'bankdetails.zip'

file_path = input("Enter image file path:")
file_name = input("Enter name of zip file:")

img_file = open(file_path, 'rb')
total_num_bytes = os.stat(file_path).st_size
print(f"{file_path}: {total_num_bytes} bytes")

# Reset file position to start
img_file.seek(0, 0)
num_bytes_read = 0

# Set up some meta data
sliding_window_size = 16
sliding_window = []
peeks_for_other_passwords = 4
num_peeks_left = 0
num_strings = 0
curr_string = ""
print("Process Starting ...")

# Read all bytes
while num_bytes_read < total_num_bytes:
    
    # Take time for time estimates
    if (num_bytes_read % PRINT_AFTER_BYTES == 0):
        tic = time.perf_counter()

    # Read byte
    curr_byte = img_file.read(1)
    if (int.from_bytes(curr_byte, byteorder='big') in printable_chars):
        char = curr_byte.decode('ascii')
        # Split string on whitespace
        if (char.isspace()):
            if curr_string != "":

                sliding_window.append(curr_string)

                # Add string as an additional potential password if peeks left
                if (num_peeks_left > 0):
                    _tmp = extract_potential_passwords(curr_string)
                    for _pass in _tmp:
                        if not (_pass in other_potential_passwords.keys()):
                            other_potential_passwords[_pass] = 1
                        else:
                            other_potential_passwords[_pass] += 1
                    num_peeks_left -= 1

                # Found file name in a string
                if (file_name.upper() in curr_string.upper()):

                    # If sliding window contains all keywords, start checking passwords
                    if (check_window_for_keywords(sliding_window)):
                        num_peeks_left = peeks_for_other_passwords
                        _tmp = extract_potential_passwords(curr_string)
                        for _pass in _tmp:
                            if not (_pass in potential_passwords.keys()):
                                potential_passwords[_pass] = 1
                            else:
                                potential_passwords[_pass] += 1

                # Keep sliding the window
                if num_strings < sliding_window_size:
                    num_strings += 1
                else:
                    sliding_window.pop(0)

            # Reset string
            curr_string = ""
        else:
            # Continue building string if char is printable
            curr_string += char
    num_bytes_read += 1

    # Print progress every 1MB of data processed
    if (num_bytes_read % PRINT_AFTER_BYTES == 0):
        toc = time.perf_counter()
        elapsed_time = toc - tic
        seconds_remaining = ((total_num_bytes - num_bytes_read) / PRINT_AFTER_BYTES) * elapsed_time
        seconds_remaining += 2
        print("%.3f %% (Estimated time left: %s)" % (num_bytes_read/total_num_bytes*100, datetime.timedelta(seconds = int(seconds_remaining))))

img_file.close()

print('')
print('----------------------')
print('')
print('Potential Passwords:')
for x, y in potential_passwords.items():
  print(f'{x} ({y} hits)')
print('')

showMore = input('Show more options (y/n):')
if showMore[0].upper() == 'Y':    
    print('----------------------')
    print('')
    print('Extra Potential Passwords:')
    for x, y in other_potential_passwords.items():
        print(f'{x} ({y} hits)')

print('')
showMore = input('Show raw signatures (y/n):')
if showMore[0].upper() == 'Y':    
    print('----------------------')
    print('')
    print('Raw signatures:')
    print(raw_signatures)