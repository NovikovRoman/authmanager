<?php

namespace AuthManager;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;

class OAuthManager implements OAuthManagerInterface
{
    /** @var OAuthClientInterface */
    private $client;
    /** @var Client */
    private $httpClient;

    public function __construct(OAuthClientInterface $client)
    {
        $this->client = $client;
        $this->httpClient = new Client();
    }

    public function signin($state, $redirect = false, array $params = []): string
    {
        $query = [
            'response_type' => 'code',
            'redirect_uri' => $this->client->getRedirectUri(),
            'client_id' => $this->client->getClientID(),
            'scope' => implode(' ', $this->client->getScope()),
            'state' => $state,
        ];

        $query = array_merge($query, $params);

        $url = $this->client->getAuthorizeURL() . '?' . http_build_query($query, '', '&');
        if ($redirect) {
            header('Location: ' . $url);
            return '';
        }
        return $url;
    }

    /**
     * @param string $url
     * @param string $state
     * @return OAuthTokenInterface
     * @throws GuzzleException
     * @throws Exception
     */
    public function getToken(string $url, string $state): OAuthTokenInterface
    {
        parse_str(parse_url($url, PHP_URL_QUERY), $params);
        if ($state != $params['state']) {
            throw new Exception(
                'Not equal state.' . json_encode($params, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
        }

        if (empty($params['code'])) {
            throw new Exception(
                'Empty code. ' . json_encode($params, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
        }

        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];

        $body = http_build_query([
            'client_id' => $this->client->getClientID(),
            'client_secret' => $this->client->getSecretKey(),
            'grant_type' => 'client_credentials',
            'code' => $params['code'],
            'redirect_uri' => $this->client->getRedirectUri(),
            'scope' => implode(' ', $this->client->getScope()),
        ]);

        $request = new Request('POST', $this->client->getTokenUrl(), $headers, $body);
        $response = $this->httpClient->send($request, ['verify' => false]);

        $json = json_decode($response->getBody()->getContents(), true);
        if (empty($json)) {
            throw new BadResponseException('Empty response', $request, $response);
        }

        $token = new OAuthToken($json);
        $this->client->setToken($token);
        return $token;
    }
}