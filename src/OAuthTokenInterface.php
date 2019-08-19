<?php

namespace AuthManager;

interface OAuthTokenInterface
{
    public function __construct(array $token);

    public function getAccessToken(): string;

    public function getTokenType(): string;

    public function getExpiresIn(): int;

    public function getRefreshToken(): string;

    public function getScope(): string;

    public function hasError(): bool;

    public function getError(): string;

    public function getErrorDescription(): string;

    public function getErrorUri(): string;
}