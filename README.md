# EasyCaptchas

A free, self-hosted and privacy-friendly CAPTCHA solution for PHP forms. EasyCaptchas uses PHP sessions and never sends visitor data to third parties.

## Installation

```bash
composer require surlinio/easycaptchas
```

Requirements: PHP 8.1 or newer, PHP sessions and the GD extension.

## Quick start

```php
<?php

session_start();
require __DIR__.'/vendor/autoload.php';

use Surlinio\EasyCaptchas\EasyCaptchas;

$captcha = new EasyCaptchas();
$challenge = $captcha->create('contact');
```

See the complete installation guide at https://easycaptchas.nl/docs.

## License

EasyCaptchas is free and open-source software released under the [MIT License](LICENSE).
