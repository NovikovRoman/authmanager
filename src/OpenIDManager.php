<?php

namespace AuthManager;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;

class OpenIDManager implements OpenIDManagerInterface
{
    private $url;
    private $returnTo;
    /** @var Client */
    private $httpClient;
    private $invalidateHandle;

    public function __construct(string $url, string $returnTo)
    {
        $this->url = $url;
        $this->returnTo = $returnTo;
        $this->httpClient = new Client();
    }

    public function signin($redirect = false): string
    {
        $pUrl = parse_url($this->returnTo);
        $params = [
            'openid.ns' => 'http://specs.openid.net/auth/2.0',
            'openid.mode' => 'checkid_setup',
            'openid.return_to' => $this->returnTo,
            'openid.realm' => $pUrl['scheme'] . '://' . $pUrl['host'],
            'openid.ns.sreg' => 'http://openid.net/extensions/sreg/1.1',
            'openid.identity' => 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.claimed_id' => 'http://specs.openid.net/auth/2.0/identifier_select',
        ];
        $url = $this->url . '?' . http_build_query($params, '', '&');
        if ($redirect) {
            header('Location: ' . $url);
            return '';
        }

        return $url;
    }

    /**
     * @param $url
     * @return string
     * @throws GuzzleException
     */
    public function getID(string $url): string
    {
        parse_str(parse_url($url, PHP_URL_QUERY), $requestParameters);
        $params = [
            'openid.assoc_handle' => $requestParameters['openid_assoc_handle'],
            'openid.signed' => $requestParameters['openid_signed'],
            'openid.sig' => $requestParameters['openid_sig'],
            'openid.ns' => $requestParameters['openid_ns'],
            'openid.op_endpoint' => $requestParameters['openid_op_endpoint'],
            'openid.claimed_id' => $requestParameters['openid_claimed_id'],
            'openid.identity' => $requestParameters['openid_identity'],
            'openid.return_to' => $this->returnTo,
            'openid.response_nonce' => $requestParameters['openid_response_nonce'],
            'openid.mode' => 'check_authentication',
        ];
        if (!empty($requestParameters['openid_claimed_id'])) {
            $claimedId = $requestParameters['openid_claimed_id'];
        } else {
            $claimedId = $requestParameters['openid_identity'];
        }

        $response = $this->httpClient
            ->request('POST', $this->discover($claimedId), ['form_params' => $params,]);

        $ar = array_diff(explode("\n", $response->getBody()->getContents()), ['']);
        $respParams = [];
        foreach ($ar as $item) {
            list($name, $value) = explode(':', $item, 2);
            $respParams[$name] = $value;
        }

        if ($respParams['is_value'] == 'true') {
            return $this->getIdFromIdentity($requestParameters['openid_identity']);
        }

        $this->invalidateHandle = empty($respParams['is_value']) ? '' : $respParams['invalidate_handle'];

        return '';
    }

    public function getInvalidateHandle(): string
    {
        return $this->invalidateHandle;
    }

    private function getIdFromIdentity($identity)
    {
        preg_match('#/openid/id/(7[0-9]{15,25})#i',
            $identity, $m);
        return empty($m[1]) ? '' : $m[1];
    }

    /**
     * @param $url
     * @return mixed
     * @throws GuzzleException
     * @throws Exception
     */
    private function discover($url)
    {
        $response = $this->httpClient->request('GET', $url);
        $contentType = $response->getHeader('Content-Type');
        if (empty($contentType) || !preg_match('#application/xrds\+xml#', $contentType[0])) {
            $e = new BadResponseException('Unexpected Content-Type', null, $response);
            throw $e;
        }

        $body = $response->getBody()->getContents();
        if (preg_match('#<URI>(.+?)</URI>#sui', $body, $m)) {
            return $m[1];
        }

        throw new Exception('URI not found. ' . $body);
    }
}