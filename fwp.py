import hashlib,binascii
import argparse
import datetime
import pprint
## The NTLM generator code was written by TrustedSec (https://www.trustedsec.com/blog/generate-an-ntlm-hash-in-3-lines-of-python/)
## Credit to HackingDave

parser = argparse.ArgumentParser(description="Find weak password hashes in your domain. This is for checking only NTLM and LM password hashes and must be in the NTDS format of user:RID:LM:NTLM::: ")
parser.add_argument('--hashfile', '-f',required=True, help="The file containing domain hashes.")
parser.add_argument('--password','-p', help="A single password you want to search for.")
parser.add_argument('--clears','-c',help="A file containing passwords you want to search for.")
parser.add_argument('--common','-m',action="store_true",help="Looking for SeasonYear and variations of 'Password'")
parser.add_argument('--show_users', '-u',action="store_true",help="Show the usernames with the found passwords")
parser.add_argument('--duplicates', '-d',action="store_true",help="Show accounts with the same password.")
args=parser.parse_args()

hashfile = args.hashfile
password = args.password
user_suggestions_file = args.clears
show_users = args.show_users
find_duplicates = args.duplicates
common = args.common

def find_dupes(hashfile):
    dupes = []
    hf = open(hashfile,"r")
    for line in hf:
        line = line.rstrip()
        parts = line.split(":")
        user = parts[0]
        ntlm = parts[3]
        hf2 = open(hashfile,"r")
        for line2 in hf2:
            line2 = line2.rstrip()
            parts2 = line2.split(":")
            user2 = parts2[0]
            ntlm2 = parts2[3]
            if (ntlm == ntlm2) and (user != user2):
                match = user + " and " + user2 + " have the same password."
                dupes.append(match)
    return dupes




# Creates an NTLM hash from a cleartext value
# Code written by HackingDave
# Arg: String:Cleartext password candidate
# Returns: String:NTLM hash
def create_ntlm(clear):
    return binascii.hexlify(hashlib.new('md4', clear.encode('utf-16le')).digest()).decode('utf-8')

# Searches the file for the presence of a non-null LanManager (LM) hash
# If found, sets the global "has_lm" flag
# Flags are read at the script's conclusion in the final_output() function
def has_lm(hashfile):
    f = open(hashfile,"r")
    for line in f:
        line = line.rstrip()
        hashes = line.split(":")
        lm_hash = hashes[2]
        if lm_hash != 'aad3b435b51404eeaad3b435b51404ee':
            return True
        else:
            continue
    return False

# Takes a hash and searches the hashfile, basically a grep
# Arg: String:NTLM password hash
# Arg: String:File of NTLM hashes, probably an NTDS.dit file
# Return: String: The username and the hash, if show_users is True, just the hash if False
def hash_search(hash,hashfile):
    file = open(hashfile,"r")
    weak = []
    weak_hash = ""
    for line in file:
        line = line.rstrip()
        if line != "":
            hashes = line.split(":")
            ntlm_hash = hashes[3]
            if hash == ntlm_hash:
                if show_users:
                    weak.append(hashes[0]+":"+hash)
                else:
                    weak.append(hash)
    return weak

# Helper function for creating weak password candidates
def get_current_year():
    x = datetime.datetime.now()
    return x.strftime("%Y")

# Function that opens the weak_passwords.txt file, hashes them and returns them in a list
def get_weak_passwords():
    weak = []
    f = open("weak_passwords.txt","r")
    for line in f:
        line = line.rstrip()
        hash = create_ntlm(line)
        weak.append(hash)
    return weak

# Function that creates various SeasonYear hashes, puts them in a list
# And calls the get_weak_passwords function, which returns a list of weak hashes
# Combines these two lists
def create_weak_hashes():
        year = int(get_current_year())
        last_year = year-1
        next_year = year+1
        seasons = ["winter","spring","summer","fall","autumn"]
        common = []
        master = []
        #for each season, add each year, for each option, append ! @ # $
        for x in seasons:
            common.append(x+str(year))
            common.append(x+str(last_year))
            common.append(x+str(next_year))
        #Uppercase the first char
        for x in common:
            master.append(x.capitalize())
        master = master + common

        #Add special char to each
        common = master.copy()
        for x in common:
            master.append(x+"!")
            master.append(x+"@")
            master.append(x+"#")
            master.append(x+"$")

        #Create list of the common passwords as NTLM hashes
        common_password_hashes = []
        for x in master:
            common_password_hashes.append(create_ntlm(x))

        # This is a hashlist that comes from the cleartext weak_passwords.txt file
        weak = get_weak_passwords()
        common_password_hashes = common_password_hashes + weak
        return common_password_hashes

# Function that takes a file of weak passwords from the user
def accept_suggestions(suggestions):
    global hashfile
    # Check the first few lines whether they are all 32 chars long, if so, they might be hashes
    # We don't want to hash a hash
    f = open(suggestions,"r")
    f2 = open(hashfile,"r")
    results = []
    for line in f:
        line = line.rstrip()
        hash = create_ntlm(line)
        for line2 in f2:
            parts = line2.split(":")
            user = parts[0]
            hash2 = parts[3]
            if hash == hash2:
                results.append(user + " has a suggested weak password.")
    return results


def search_common_weak():
    global hashfile
    global show_users
    result_list = []
    weak_hashes = create_weak_hashes()
    f = open(hashfile,"r")
    for line in f:
        line = line.rstrip()
        line_parts = line.split(":")
        ntlm_hash = line_parts[3]
        user = line_parts[0]
        if ntlm_hash in weak_hashes:
            result_list.append(user+" has a known weak password.")
    return result_list

def main():
    # Check for LM
    if has_lm(hashfile):
        print("At least one LanManager (LM) hash was found.")
    else:
        print("No LanManager (LM) hashes were found.")

    # If a single pass, check it
    if(password):
        hash = create_ntlm(password)
        value = hash_search(hash,hashfile)
        if len(value) > 0:
            pprint.pprint(value)
        else:
            print("No users found with "+password+" for their password.")

    # Look for default suggested weak passwords
    # Load up the weak passwords.txt file
    # Add an if flag for whether we want to look for default files
    if common:
        pprint.pprint(search_common_weak())

    # Accept a file of suggested passwords and look for default weak
    # Read suggestions, put pw in a variable, hash it
    # Read through hashfile, compare
    if user_suggestions_file:
        res = accept_suggestions(user_suggestions_file)
        if len(res) == 0:
            print("None of the passwords in " + user_suggestions_file + " were found.")
        else:
            pprint.pprint(res)

    if find_duplicates:
        dupes = find_dupes(hashfile)
        if len(dupes) == 0:
            print("No duplicate hashes found.")
        else:
            pprint.pprint(dupes)

if __name__ == "__main__":
    main()
