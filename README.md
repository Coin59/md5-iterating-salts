# md5-iterating-salts

This project was made out of boredom. It uses the common "salting" operation on hashing algorithms to create hashes that have a different type of salt. 

## Warning
Do not use this program for any databases or similar you want to keep secure. In the case of a databreach, it would be trivial to make a small program to crack hashes generated using this program. This was made for fun and is not meant for widespread usage or implementation.

## Usage
options:
```
  -h, --help ------------------------------ show this help message and exit ----------------------------------------
  -p PASSWORD, --password PASSWORD -------- the password to hash ---------------------------------------------------
  -s SALT, --salt SALT -------------------- the salt to use --------------------------------------------------------
  -a ALGORITHM, --algorithm ALGORITHM ----- the hashing algorithm to use (md5, sha1, sha256, sha512 supported) -----
```
                       
`python main.py -p password -s salt -a md5`
this will generate an md5 hash using password "password" and iterating salt "salt"

`python main.py -p 111111111 -s salt -a sha1`
this will generate a sha1 hash using password "111111111" with salt "salt". The plaintext will be "1s1a1l1t1s1a1l1t1s"

## Libraries used
- hashlib, used to create hashes
- argparse, used to parse arguments from the command line

## License

[MIT](https://choosealicense.com/licenses/mit/)
