# PHP Encrypter

This project encrypts and decrypts the given value. It uses OpenSSL extension with AES-256 cipher for encryption and HMAC-SHA-256 for hash. The encryption and hash can use different keys.

PHP Encrypter requires PHP 5.3 or higher, OpenSSL and Multibyte String extensions.

## Installation

#### With [Composer](https://getcomposer.org/):

```
composer require adbario/php-encrypter
```

#### Manual installation:
1. Download the latest release
2. Extract the files into your project
3. Require "/path/to/php-encrypter/src/Encrypter.php";
4. If your PHP version is lower than 7, also [polyfill for random_bytes()](https://github.com/paragonie/random_compat) is required

## Usage

Setup the encryption key:

```php
$key = '+NeXrQhAEhW}g8gf^y)Up8hAUKpue7wb';
```

**Change the key to your own custom random 32 character string.**

Create a new encrypter instance:

```php
$encrypter = new \Adbar\Encrypter($key);
```

If you wish to use a different key for hashing, you can pass it to constructor as a second parameter:

```php
$encrypter = new \Adbar\Encrypter($key, $authKey);
```

### Encryption

Encrypt a string:

```php
$string = 'This is my string to encrypt.';
$encrypted = $encrypter->encryptString($string);
```

Encrypt other variable types with serialization:

```php
$array = array('key' => 'value');
$encrypted = $encrypter->encrypt($array);
```

### Decryption

Decrypt a string:

```php
$string = $encrypter->decryptString($encrypted);
```

Decrypt other variable types with serialization:

```php
$array = $encrypter->decrypt($encrypted);
```

## License

[MIT license](LICENSE.md)
