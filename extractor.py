import os
import time
import datetime
import string

# Settings
PRINT_AFTER_BYTES = 1048576 # Interval (in number of bytes) to print progress report
printable_chars = set(bytes(string.printable, 'ascii')) # Which bytes to consider as valid characters
keywords = ['ADMINI', 'DOCUME', 'LOCALS'] # Keywords (from the experiment footprints) that appear before the password
separator = ']||' # The separator that indicates the start of the password
sliding_window_size = 16 # Number of strings to hold in the window (which is checked for the keywords after finding the file name)
peeks_for_other_passwords = 4 # Number of strings to check for passwords that aren't in the window yet (bytes to the right of the window)

file_path = input("Enter image file path:") # Relative path from the python script to the image file
file_name = input("Enter name of zip file:") # Name of the (zip) file (with its extension) which was password protected


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
    index = signature.find(separator)
    if (index >= 0):
        passwords = signature.split(separator)
        return passwords[1:]
    return []


# Helper function for printing out the passwords
def print_passwords():    
    print('')
    print('----------------------')
    print('')
    print('Potential Passwords:')
    num_passwords = len(potential_passwords.items())
    for x, y in potential_passwords.items():
        print(f'[{y} hits]: {x}')
    print('')


# Get the size of the file
img_file = open(file_path, 'rb')
total_num_bytes = os.stat(file_path).st_size
print(f"{file_path}: {total_num_bytes} bytes")

# Reset file position to start
img_file.seek(0, 0)
num_bytes_read = 0
status_num = 0
avg_elapsed_time = 0

# Set up some meta data
sliding_window = []
potential_passwords = {}
raw_signatures = []
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
                        if not (_pass in potential_passwords.keys()):
                            potential_passwords[_pass] = 1
                        else:
                            potential_passwords[_pass] += 1
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
        avg_elapsed_time = (avg_elapsed_time * status_num + elapsed_time) / (status_num + 1)
        status_num += 1
        seconds_remaining = ((total_num_bytes - num_bytes_read) / PRINT_AFTER_BYTES) * avg_elapsed_time
        seconds_remaining += 2
        print("%.3f %% (Estimated time left: %s)" % (num_bytes_read/total_num_bytes*100, datetime.timedelta(seconds = int(seconds_remaining))))

img_file.close()

# Print findings
print_passwords()
print('')
showMore = input('Show raw signatures (y/n):')
if showMore[0].upper() == 'Y':    
    print('----------------------')
    print('')
    print('Raw signatures:')
    for signature in raw_signatures:
        print(signature)