<?php
declare(strict_types=1);

/**
 * セッションのライフサイクル（発行・有効・延長・失効・破棄）を確認する小さなサンプル。
 * 入力検証と状態遷移の検証のみを扱い、DB・フレームワーク・外部通信に依存しない。
 * 時刻は呼び出し側から渡すため、すべての挙動が決定的に確認できる。
 */

final class SessionStore
{
    /** @var array<string, array{user:string, expires:int, revoked:bool}> */
    private array $sessions = [];

    private int $seq = 0;

    /** @return array{status:string, token?:string, expires_at?:int, reason?:string} */
    public function issue(string $userId, int $now, int $ttlSeconds): array
    {
        if (trim($userId) === '') {
            return ['status' => 'invalid', 'reason' => 'empty_user_id'];
        }
        if ($ttlSeconds <= 0) {
            return ['status' => 'invalid', 'reason' => 'non_positive_ttl'];
        }
        $this->seq++;
        $token = 'sess-' . $this->seq;
        $this->sessions[$token] = [
            'user' => $userId,
            'expires' => $now + $ttlSeconds,
            'revoked' => false,
        ];
        return ['status' => 'active', 'token' => $token, 'expires_at' => $now + $ttlSeconds];
    }

    /** @return array{status:string, user?:string} */
    public function validate(string $token, int $now): array
    {
        if (!array_key_exists($token, $this->sessions)) {
            return ['status' => 'unknown'];
        }
        $session = $this->sessions[$token];
        if ($session['revoked']) {
            return ['status' => 'revoked'];
        }
        if ($now >= $session['expires']) {
            return ['status' => 'expired'];
        }
        return ['status' => 'active', 'user' => $session['user']];
    }

    /** @return array{status:string, expires_at?:int, reason?:string} */
    public function refresh(string $token, int $now, int $ttlSeconds): array
    {
        if (!array_key_exists($token, $this->sessions)) {
            return ['status' => 'unknown'];
        }
        if ($this->sessions[$token]['revoked']) {
            return ['status' => 'revoked'];
        }
        if ($now >= $this->sessions[$token]['expires']) {
            return ['status' => 'expired'];
        }
        if ($ttlSeconds <= 0) {
            return ['status' => 'invalid', 'reason' => 'non_positive_ttl'];
        }
        $this->sessions[$token]['expires'] = $now + $ttlSeconds;
        return ['status' => 'active', 'expires_at' => $now + $ttlSeconds];
    }

    /** @return array{status:string} */
    public function revoke(string $token): array
    {
        if (!array_key_exists($token, $this->sessions)) {
            return ['status' => 'unknown'];
        }
        $this->sessions[$token]['revoked'] = true;
        return ['status' => 'revoked'];
    }
}
