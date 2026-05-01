<?php

declare(strict_types=1);

namespace Clawdrey\AAuth;

/**
 * Base class for all aauth-php exceptions. Catch this if you don't care
 * about the specific failure mode; otherwise catch the subclasses.
 */
class AAuthException extends \RuntimeException {}

/** Headers missing or malformed. */
class MalformedRequestException extends AAuthException {}

/** Cryptographic verification failed. */
class InvalidSignatureException extends AAuthException {}

/** Token expired, not-yet-valid, or fails freshness window. */
class TokenLifetimeException extends AAuthException {}

/** Could not retrieve a public key for the given identifier. */
class KeyResolutionException extends AAuthException {}

/** Caller's `created` timestamp outside acceptable window. */
class StaleSignatureException extends AAuthException {}

/** Request authority does not match this verifier's accepted authorities. */
class WrongAudienceException extends AAuthException {}

/** Unsupported scheme/algorithm/JWK type. */
class UnsupportedException extends AAuthException {}
