<?php

namespace AuthManager;

class OAuthToken implements OAuthTokenInterface
{

    private $accessToken;
    private $tokenType;
    private $expiresIn;
    private $expiresAt;
    private $refreshToken;
    private $scope;

    private $error;
    private $errorDescription;
    private $errorUri;

    public function __construct(array $token)
    {
        $this->accessToken = empty($token['access_token']) ? '' : $token['access_token'];
        $this->tokenType = empty($token['token_type']) ? '' : $token['token_type'];
        $this->expiresIn = empty($token['expires_in']) ? 0 : $token['expires_in'];
        $this->expiresAt = time() + $this->expiresIn;
        $this->refreshToken = empty($token['refresh_token']) ? '' : $token['refresh_token'];
        $this->scope = '';
        if (!empty($token['scope'])) {
            $this->scope = is_array($token['scope']) ? implode(' ', $token['scope']) : $token['scope'];
        }

        $this->error = empty($token['error']) ? '' : $token['error'];
        $this->errorDescription = empty($token['error_description']) ? '' : $token['error_description'];
        $this->errorUri = empty($token['error_uri']) ? '' : $token['error_uri'];
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getTokenType(): string
    {
        return $this->tokenType;
    }

    public function getExpiresIn(): int
    {
        return $this->expiresIn;
    }

    public function isExpired(): bool
    {
        return $this->expiresAt < time();
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function hasError(): bool
    {
        return !!$this->error;
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function getErrorDescription(): string
    {
        return $this->errorDescription;
    }

    public function getErrorUri(): string
    {
        return $this->errorUri;
    }
}