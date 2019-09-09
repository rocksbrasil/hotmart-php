<?php
class hotmart{
    private $clientId, $clientSecret, $basicHash;// variáveis de autenticação
    private $accessToken, $tokenType, $tokenExpiresIn;// variáveis de retorno da api
    private $onErrorFunc; // variáveis de funções
    function __construct($clientId, $clientSecret, $basicHash){
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->basicHash = $basicHash;
        return true;
    }
    function credentialsAuth(){
        $retorno = $this->curlConnect('https://api-sec-vlc.hotmart.com/security/oauth/token', Array(
            'grant_type' => 'client_credentials',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ), true, Array(
            'Authorization: Basic '.$this->basicHash,
        ));
        if(isset($retorno['access_token']) && isset($retorno['token_type']) && $retorno['expires_in']){
            $this->accessToken = $retorno['access_token'];
            $this->tokenType = $retorno['token_type'];
            $this->tokenExpiresIn = $retorno['expires_in'];
            return true;
        }
        return false;
    }
    function codeAuth($code, $redirectUrl, &$authData = false){
        $retorno = $this->curlConnect('https://api-sec-vlc.hotmart.com/security/oauth/token', Array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUrl,
        ), true, Array(
            'Authorization: Basic '.$this->basicHash,
        ));
        if(isset($retorno['access_token']) && isset($retorno['token_type']) && $retorno['expires_in']){
            $this->accessToken = $retorno['access_token'];
            $this->tokenType = $retorno['token_type'];
            $this->tokenExpiresIn = $retorno['expires_in'];
            $authData = Array(
                'access_token' => $this->accessToken,
                'token_type' => $this->tokenType,
                'expires_in' => $this->tokenExpiresIn,
            );
            return true;
        }
        return false;
    }
    function tokenAuth($accessToken, $tokenType){
        $this->accessToken = $accessToken;
        $this->tokenType = $tokenType;
        return true;
    }
    function authorizeUrl($redirectUrl){
        return 'https://api-sec-vlc.hotmart.com/security/oauth/authorize?'.http_build_query(Array(
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUrl,
        ));
    }
    function getAuthData(){
        return Array(
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->tokenExpiresIn,
        );
    }
    function get($endpointUrl, $parameters = null){
        $this->checkAuth();
        $retorno = $this->curlConnect($endpointUrl, $parameters, false, Array(
            'Authorization: '.$this->tokenType.' '.$this->accessToken,
        ));
        return $retorno;
    }
    private function checkAuth(){
        if(!$this->accessToken || !$this->tokenType){
            $this->throwError('require-auth', 'Require authentication!');
        }
        return true;
    }
    private function curlConnect($url, $get = null, $post = null, $headers = null, $timeout = 5){
        if($get && !empty($get)){
            $url = trim($url, ' /') . '?' . http_build_query($get);
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        if($post){
            curl_setopt($ch, CURLOPT_POST, 1);
        }
        if (!empty($post)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        }
        if ($headers && !empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        $returnData = curl_exec($ch);
        curl_close($ch);
        if($jsonDecoded = @json_decode($returnData, true)){
            $this->analyseReturnErrors($jsonDecoded);
            return $jsonDecoded;
        }else{
            $this->throwError('invalid-return', $returnData);
        }
        return $returnData;
    }
    private function analyseReturnErrors($returnData){
        if(isset($returnData['error'])){
            $this->throwError($returnData['error'], $returnData['error_description']);
            return false;
        }
        return true;
    }
    private function throwError($code, $description){
        if($this->onErrorFunc && is_callable($this->onErrorFunc)){
            if(call_user_func($this->onErrorFunc, $code, $description)){
                return true;
            }
        }
        throw new Exception('Hotmart API Error: ['.$code.'], '.$description);
        return true;
    }
    function onError($errorFunc){
        if(is_callable($errorFunc)){
            $this->onErrorFunc = $errorFunc;
            return true;
        }
        return false;
    }
}
