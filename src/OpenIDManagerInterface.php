<?php

namespace AuthManager;

interface OpenIDManagerInterface
{
    public function __construct(string $url, string $returnTo);

    public function signin($redirect = false): string;

    public function getID(string $url): string;

    public function getInvalidateHandle(): string;
}