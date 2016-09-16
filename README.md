# mod_crypt

THIS IS A **PROOF-OF-CONCEPT** project i made for my graduation thesis at the third year.

If you are interested in the project, [you can read the thesis clicking here](https://drive.google.com/file/d/0B-KyKgTmIXNAZW93eTFDNDViOVE/view?usp=sharing). Feel free to contact me in case you have somethink to say about it.

`mod_crypt` is an apache module that provides per-user file encryption

In the directories this module is enabled, Apache will return an encrypted copy of the requested files, using a user-specific key.

The user authentication is a simple `?user=user_id` querystring on the request: there is no need of passwords or private tokens here, the layer of security is provided by the encryption itself.

Note that encrypted file will be returned with an `application/octet-stream` mimetype

## Installation and configuration
This is created and tested only for GNU/Linux systems. You also need to have Apache and Openssl already installed

Clone this repository (or download it), enter the directory and compile mod_crypt.c by running:
```
# apxs -i -a -c -n crypt mod_crypt.c -lcrypto
```

Cool! the module now should be up and running, but you are not done yet.

On the directories you want to enable, add the following directive in your .htaccess (as provided in the .htaccess of this repository):
```
SetHandler crypt-handler
```

### ACL file
Well, probably not every user should be allowed to see all the files on the directory, right?
That's why you can set an Access Control List with a simple .csv file.
As you can see in the `acl.csv.example`, the row format is the following:
```
file_path;list,user,allowed;
```

The first row is the header and it will not be processed, so a super-minimal acl.csv should look like this:
```
path;users_allowed;
secretFile.txt;John,Giorgio;
superSecretFile.txt;Giorgio;
```

Given this ACL, `../secretFile.txt?user=John` will return the secretFile.txt encrpyted for John, while `../superSecretFile.txt?user=John` will return a 403 error.

There are two Apache directives that provides a better acl customisation, just include them in your apache config file:
```
CryptRootPath /path/to/your/directory/
CryptAclFile /path/to/your/directory/acl.csv
```

`CryptRootPath` provides the root path of files in your acl, so you don't need to specify it everytime in your `acl.csv`

If not specified, the default is `/`


`CryptAclFile` just provides the path of Acl file. Default is `CryptRootPath/acl.csv`. Remember that http user will need read access to those files

### KEY files
Every user need to provide his public `.pem` RSA key to the server. `mod_crypt` will use the .pem file with the requesting user as filename, searching into a specific directory.

The directory can be set in the apache configuration file as well:
```
CryptKeysRoot /path/to/keys
```
