<?php

declare(strict_types=1);

namespace Surlinio\EasyCaptchas;

use RuntimeException;

final class EasyCaptchas
{
    private const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    private const SESSION_KEY = 'easycaptcha_challenges';

    public function __construct(
        private readonly int $ttlSeconds = 300,
        private readonly int $maxAttempts = 3,
        private readonly int $length = 6,
    ) {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new RuntimeException('Start the PHP session before using EasyCaptchas.');
        }

        if ($ttlSeconds < 1 || $maxAttempts < 1 || $length < 4 || $length > 12) {
            throw new RuntimeException('Use valid values for the lifetime, attempt limit and code length.');
        }
    }

    /** @return array{id: string, expires_at: int} */
    public function create(string $scope = 'default'): array
    {
        $this->prune();
        $id = bin2hex(random_bytes(18));
        $answer = '';
        $max = strlen(self::ALPHABET) - 1;

        for ($index = 0; $index < $this->length; $index++) {
            $answer .= self::ALPHABET[random_int(0, $max)];
        }

        $expiresAt = time() + $this->ttlSeconds;
        $_SESSION[self::SESSION_KEY][$id] = [
            'answer_hash' => hash_hmac('sha256', $answer, $this->sessionSecret()),
            'plain_answer' => $answer,
            'scope' => $scope,
            'expires_at' => $expiresAt,
            'attempts' => 0,
        ];

        return ['id' => $id, 'expires_at' => $expiresAt];
    }

    public function verify(string $id, string $answer, string $scope = 'default'): bool
    {
        $this->prune();
        $challenge = $_SESSION[self::SESSION_KEY][$id] ?? null;

        if (!is_array($challenge) || !hash_equals((string) $challenge['scope'], $scope)) {
            return false;
        }

        $_SESSION[self::SESSION_KEY][$id]['attempts']++;
        $normalised = strtoupper(preg_replace('/[^A-Z0-9]/i', '', $answer) ?? '');
        $valid = hash_equals(
            (string) $challenge['answer_hash'],
            hash_hmac('sha256', $normalised, $this->sessionSecret()),
        );

        if ($valid || $_SESSION[self::SESSION_KEY][$id]['attempts'] >= $this->maxAttempts) {
            unset($_SESSION[self::SESSION_KEY][$id]);
        }

        return $valid;
    }

    public function renderPng(string $id, string $scope = 'default', int $width = 250, int $height = 82): string
    {
        $this->prune();
        $challenge = $_SESSION[self::SESSION_KEY][$id] ?? null;

        if (!is_array($challenge) || !hash_equals((string) $challenge['scope'], $scope)) {
            throw new RuntimeException('The CAPTCHA does not exist or has expired.');
        }

        $answer = (string) ($challenge['plain_answer'] ?? '');
        if ($answer === '') {
            throw new RuntimeException('The CAPTCHA image has already been retrieved.');
        }

        unset($_SESSION[self::SESSION_KEY][$id]['plain_answer']);
        $image = imagecreatetruecolor($width, $height);
        if ($image === false) {
            throw new RuntimeException('The CAPTCHA image could not be created.');
        }

        $background = imagecolorallocate($image, 244, 248, 252);
        $ink = imagecolorallocate($image, 18, 42, 64);
        $accent = imagecolorallocate($image, 20, 154, 140);
        $noise = imagecolorallocatealpha($image, 36, 74, 101, 78);
        imagefill($image, 0, 0, $background);

        for ($line = 0; $line < 9; $line++) {
            imageline($image, random_int(0, $width - 1), random_int(0, $height - 1), random_int(0, $width - 1), random_int(0, $height - 1), $line % 3 === 0 ? $accent : $noise);
        }

        for ($dot = 0; $dot < 150; $dot++) {
            imagesetpixel($image, random_int(0, $width - 1), random_int(0, $height - 1), $noise);
        }

        $spacing = max(1, intdiv($width - 36, max(1, strlen($answer))));
        foreach (str_split($answer) as $index => $character) {
            imagestring($image, 5, 18 + $index * $spacing, random_int(25, max(25, $height - 45)), $character, $index % 2 ? $accent : $ink);
        }

        ob_start();
        imagepng($image);
        imagedestroy($image);
        $png = ob_get_clean();

        if (!is_string($png)) {
            throw new RuntimeException('The CAPTCHA image could not be rendered.');
        }

        return $png;
    }

    private function prune(): void
    {
        $now = time();
        foreach ($_SESSION[self::SESSION_KEY] ?? [] as $id => $challenge) {
            if (!is_array($challenge) || (int) ($challenge['expires_at'] ?? 0) < $now) {
                unset($_SESSION[self::SESSION_KEY][$id]);
            }
        }
    }

    private function sessionSecret(): string
    {
        if (empty($_SESSION['easycaptcha_secret'])) {
            $_SESSION['easycaptcha_secret'] = bin2hex(random_bytes(32));
        }

        return (string) $_SESSION['easycaptcha_secret'];
    }
}
