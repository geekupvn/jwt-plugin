<?php
namespace GUCMS\Plugin;

use Firebase\JWT\JWT as FirebaseJWT;

class JWT extends FirebaseJWT
{
  private $_options;

  public function __construct($options = null) {
    if (!isset($options['key'])) {
      throw new \Exception('An encryption key is required');
    }
    if (!isset($options['lifetime'])) {
      throw new \Exception('An Life time is required');
    }
    if (!isset($options['global_domain'])) {
      throw new \Exception('An Local Domain is required');
    }

    $this->_options = $options;
  }

  public function encoder($payload = [], $options = []) {
    $options = array_merge($options, $this->_options);

    $now = time();
    $payload['jti'] = isset($payload['id']) ? $payload['id'] : "";
    $payload['iat'] = $now;
    $payload['nbf'] = $now;
    $payload['exp'] = $now + $options['lifetime'];
    $payload = array_filter($payload);

    return self::encode($payload, $options['key']);
  }

  public function decoder($jwt, $key = null) {
    return self::decode($jwt, isset($key) ? $key : $this->_options['key'], ['HS256', 'HS512', 'HS384']);
  }
}