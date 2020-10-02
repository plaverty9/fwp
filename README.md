# Find Weak Passwords
A script that will find weak passwords in an Active Directory domain without cracking passwords. Grab the NTDS and find common weak passwords, submit suggested weak passwords, find LanManager passwords and find accounts with duplicate passwords.

This script works by doing a hash comparision. It finds LM passwords by looking for non-nulled hashes. It can find known weak passwords by creating its own list of weak passwords and hashing them and then comparing those to your hashes. You can also upload your own file of weak passwords, one per line, to see if any users have that password.

optional arguments:
  -h, --help            show this help message and exit
  --hashfile HASHFILE, -f HASHFILE
                        The file containing domain hashes.
  --password PASSWORD, -p PASSWORD
                        A single password you want to search for.
  --clears CLEARS, -c CLEARS
                        A file containing passwords you want to search for.
  --common, -m          Looking for SeasonYear and variations of 'Password'
  --show_users, -u      Show the usernames with the found passwords
  --duplicates, -d      Show accounts with the same password.
