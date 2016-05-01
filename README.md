# mod_crypt
Apache module that provides per-user file encryption

In the directories it is enabled, Apache will return an AES-encrypted copy of the requested files, using a user-specific key

The user authentication is a simple `?user=user_id` querystring: you are allowed to act as a different user because without the proper key you can't read the data anyway

Note that encrypted file will be returned with an `application/octet-stream` mimetype

## Installation and configuration
This is created and tested only for GNU/Linux systems. You also need to have Apache and Openssl already installed

Clone this repository (or download it), enter the directory and compile mod_crypt.c by running:
```
sudo apxs -i -a -c -n crypt mod_crypt.c
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

The first row is the header and will not be processed, so a super-minimal acl.csv should look like this:
```
path;users_allowed;
secretFile.txt;John,Giorgio;
superSecretFile.txt;Giorgio;
```

Given this ACL, `../secretFile.txt?user=John` will return the secretFile.txt encrpyted with John key, while `../superSecretFile.txt?user=John` will return a 403

There are two Apache directives that provides a better acl customisation, just include them in your apache config file:
```
CryptRootPath /path/to/root/directory/
CryptAclFile /path/to/root/directory/acl.csv
```

`CryptRootPath` provides the root path of files in your acl, so that your acl.csv can go from

```
home/user/www/foler/secretFile.txt;John,Giorgio;
home/user/www/foler/superSecretFile.txt;Giorgio;
```

to
```
secretFile.txt;John,Giorgio;
superSecretFile.txt;Giorgio;
```

just by adding `CryptRootPath /home/user/www/foler/` to your apache .conf

If not specified, the default is `/`


`CryptAclFile` just provide the path of Acl file. Default is `CryptRootPath/acl.csv`

### KEY file

TODO: probably will change in the last commits after RSA key encryption
