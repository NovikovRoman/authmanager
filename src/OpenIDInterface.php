<?php

namespace AuthManager;

interface OpenIDInterface
{
    public function signin($redirect): string;

    public function getID($code): string;
}