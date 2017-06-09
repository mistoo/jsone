# JSONe

`jsone` is a [ejson](https://github.com/Shopify/ejson) clone but written in Ruby. Utility encrypts strings in JSON files using public key cryptography (thanks to [rbnacl](https://github.com/cryptosphere/rbnacl)'s [SimpleBox](https://github.com/cryptosphere/rbnacl/wiki/SimpleBox)).

## Installation
```
gem install jsone
```

## Usage

### 1: Create `keys` directory

By default, looks for keys in `/opt/jsone/keys`. You can change this by setting `JSONE_KEYDIR`

```
$ mkdir -p /etc/jsone/keys
```

### 2: Generate a key pair

```
$ jsone keygen
Key pair has been saved to /etc/jsone/keys/d586f99465b6f1dc7ff37c604e8e875eafbcf7770206fbb14473f3792065613c

   JSONE_KEY=d586f99465b6f1dc7ff37c604e8e875eafbcf7770206fbb14473f3792065613c
   export JSONE_KEY

to your environment for convenience.
```

With `--env` option JSONE_KEY will be added to `.env` file if it exists

### 3: Encrypting

```json
$ cat config.json
{
  "api_key": "123qwerty",
  "password": "123143",
  "foo": "bar"
}
$ export JSONE_KEY=d586f99465b6f1dc7ff37c604e8e875eafbcf7770206fbb14473f3792065613c
$ jsone encrypt config.json -v 
* encrypting config.json with d586f99465b6f1dc7ff37c604e8e875eafbcf7770206fbb14473f3792065613c
```

Encrypted files are saved with `.jsone` extension:
```json
$ cat config.jsone
{
  "__jsone_public_key": "d586f99465b6f1dc7ff37c604e8e875eafbcf7770206fbb14473f3792065613c",
  "api_key": "__!jsone__J5zMgvtZ93uUr6bkkfZ8pKXyqkhSfWRdokyg34fHCrYbY5ec6t3VPN+fCgld\ndGsY6w==\n",
  "password": "__!jsone__13E6u2fpA1Z3snWPQo1f2NDZhtcVHoAOrc4U19bG+UCNQ1cKki7aDP9VkSs9\nSg==\n",
  "foo": "__!jsone__eisgcjhKityeO1ykA59L7/R6Sd5USSV7XChHWqHf1eIiAjAjffL5AoaBoQ==\n"
}
```

### 4: Decrypting

With `decrypt` command file will be decrypted and saved back as `.json`

```json
$ json decrypt config.jsone -v
* decrypting config.jsone
$ cat config.jsone
{
  "__jsone_public_key": "d586f99465b6f1dc7ff37c604e8e875eafbcf7770206fbb14473f3792065613c",
  "api_key": "123qwerty",
  "password": "123143",
  "foo": "bar"
}
```

### Notes

* `jsone encrypt DIR` and `jsone decrypt DIR` will recursively encrypts/decrypts all JSON(e) files in DIR
* with `--stdout` encryption/decrption results will be printed to stdout
* `jsone` load `PWD/.env` file at start (using [dotenv](https://github.com/bkeepers/dotenv))


## See also

* [ejson](https://github.com/Shopify/ejson)

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

