<?php

namespace AuthManager;

interface OAuthClientInterface
{
    public function __construct($id, $secret, $scope, $redirectUri);

    public function getAuthorizeURL(): string;

    public function getTokenUrl(): string;

    public function getClientID(): string;

    public function getSecretKey(): string;

    public function getRedirectUri(): string;

    public function getScope(): array;

    public function setToken(OAuthTokenInterface $token);

    public function getToken(): OAuthTokenInterface;
}