<?php

declare(strict_types=1);

namespace Clawdrey\AAuth;

/**
 * Convert ECDSA P-256 signatures between RFC 9421 wire format (raw r||s, 64 bytes)
 * and ASN.1 DER (what OpenSSL's verify() expects).
 *
 * Why this matters: RFC 9421 §3.3.1 specifies ecdsa-p256-sha256 signatures as
 * the raw concatenation of r and s, each padded to 32 bytes. PHP's
 * openssl_verify() only accepts DER-encoded ECDSA-Sig-Value. So every PHP
 * implementation of RFC 9421 needs this conversion.
 *
 * (Christian Posta's aauth_signing==0.1.2 uses the standard
 * `http_message_signatures` Python library which handles this internally;
 * we don't get that for free in PHP.)
 */
final class EcdsaWire
{
    private const COMPONENT_LEN_P256 = 32;

    /**
     * Convert raw r||s (64 bytes for P-256) to ASN.1 DER ECDSA-Sig-Value.
     *
     * The DER encoding is a SEQUENCE of two INTEGERs:
     *
     *   ECDSA-Sig-Value ::= SEQUENCE {
     *     r INTEGER,
     *     s INTEGER
     *   }
     *
     * Note ASN.1 INTEGERs are signed two's-complement, so if the high bit of
     * the first byte is set we MUST prepend 0x00 to keep the value positive.
     *
     * @throws \InvalidArgumentException if input is not 64 bytes
     */
    public static function rawToDer(string $raw): string
    {
        $expected = self::COMPONENT_LEN_P256 * 2;
        if (strlen($raw) !== $expected) {
            throw new \InvalidArgumentException(sprintf(
                'expected %d bytes for P-256 raw signature, got %d',
                $expected,
                strlen($raw)
            ));
        }

        $r = substr($raw, 0, self::COMPONENT_LEN_P256);
        $s = substr($raw, self::COMPONENT_LEN_P256, self::COMPONENT_LEN_P256);

        $rEncoded = self::encodeAsn1Integer($r);
        $sEncoded = self::encodeAsn1Integer($s);

        $body = $rEncoded . $sEncoded;
        return "\x30" . self::encodeAsn1Length(strlen($body)) . $body;
    }

    /**
     * Convert ASN.1 DER ECDSA-Sig-Value back to raw r||s (64 bytes for P-256).
     *
     * Accepts the full SEQUENCE encoding and returns the canonical r||s with
     * each component left-padded to 32 bytes.
     *
     * @throws \InvalidArgumentException if input is not a well-formed
     *         ECDSA-Sig-Value, or if r or s is too long for P-256.
     */
    public static function derToRaw(string $der): string
    {
        $offset = 0;
        $len = strlen($der);

        if ($len < 2 || $der[$offset] !== "\x30") {
            throw new \InvalidArgumentException('expected ASN.1 SEQUENCE tag (0x30)');
        }
        $offset++;

        [$seqLen, $seqLenBytes] = self::decodeAsn1Length($der, $offset);
        $offset += $seqLenBytes;
        if ($offset + $seqLen !== $len) {
            throw new \InvalidArgumentException('ASN.1 SEQUENCE length mismatch');
        }

        // r INTEGER
        if ($der[$offset] !== "\x02") {
            throw new \InvalidArgumentException('expected ASN.1 INTEGER tag for r');
        }
        $offset++;
        [$rLen, $rLenBytes] = self::decodeAsn1Length($der, $offset);
        $offset += $rLenBytes;
        $r = substr($der, $offset, $rLen);
        $offset += $rLen;

        // s INTEGER
        if ($der[$offset] !== "\x02") {
            throw new \InvalidArgumentException('expected ASN.1 INTEGER tag for s');
        }
        $offset++;
        [$sLen, $sLenBytes] = self::decodeAsn1Length($der, $offset);
        $offset += $sLenBytes;
        $s = substr($der, $offset, $sLen);

        return self::normalizeAsn1Integer($r) . self::normalizeAsn1Integer($s);
    }

    /**
     * Encode a fixed-width unsigned big-endian integer (the r or s value)
     * as an ASN.1 INTEGER. Strips leading zeros, then prepends 0x00 if
     * needed to disambiguate from a negative number.
     */
    private static function encodeAsn1Integer(string $component): string
    {
        // Strip leading zero bytes.
        $component = ltrim($component, "\x00");
        // ASN.1 INTEGER 0 is a single 0x00 byte, not the empty string.
        if ($component === '') {
            $component = "\x00";
        }
        // Prepend 0x00 if high bit is set (so it's interpreted as positive).
        if ((ord($component[0]) & 0x80) !== 0) {
            $component = "\x00" . $component;
        }
        return "\x02" . self::encodeAsn1Length(strlen($component)) . $component;
    }

    /**
     * Strip the optional leading 0x00 from an ASN.1 INTEGER and left-pad the
     * remaining magnitude to COMPONENT_LEN_P256 bytes.
     *
     * @throws \InvalidArgumentException if the magnitude is longer than
     *         COMPONENT_LEN_P256 bytes.
     */
    private static function normalizeAsn1Integer(string $integer): string
    {
        // Drop the leading 0x00 if present (it was added to disambiguate sign).
        if (strlen($integer) > 0 && $integer[0] === "\x00") {
            $integer = substr($integer, 1);
        }
        if (strlen($integer) > self::COMPONENT_LEN_P256) {
            throw new \InvalidArgumentException(sprintf(
                'ASN.1 INTEGER too long for P-256: %d bytes',
                strlen($integer)
            ));
        }
        return str_pad($integer, self::COMPONENT_LEN_P256, "\x00", STR_PAD_LEFT);
    }

    /**
     * Encode a non-negative length in ASN.1 BER short or long form.
     */
    private static function encodeAsn1Length(int $len): string
    {
        if ($len < 0) {
            throw new \InvalidArgumentException('length must be non-negative');
        }
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xFF) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Decode an ASN.1 BER length starting at $offset.
     *
     * @return array{0: int, 1: int} [length, bytes consumed]
     */
    private static function decodeAsn1Length(string $der, int $offset): array
    {
        $first = ord($der[$offset]);
        if ($first < 0x80) {
            return [$first, 1];
        }
        $numBytes = $first & 0x7F;
        if ($numBytes === 0 || $numBytes > 4) {
            // BER allows indefinite length (0) but DER does not; we don't
            // need lengths > 2^32 either. Reject.
            throw new \InvalidArgumentException('unsupported ASN.1 length form');
        }
        $len = 0;
        for ($i = 1; $i <= $numBytes; $i++) {
            $len = ($len << 8) | ord($der[$offset + $i]);
        }
        return [$len, $numBytes + 1];
    }
}
