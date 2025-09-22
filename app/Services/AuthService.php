<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use App\Http\Resources\UserResource;
use Exception;
use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;

class AuthService
{
    protected $user;
    private const ACCESS_TOKEN_EXPIRES_IN = 15; // minutes
    private const REFRESH_TOKEN_EXPIRES_IN = 7; // days

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    public function register(array $userData): array
    {
        try {
            DB::beginTransaction();

            $user = $this->user->create([
                'name' => $userData['name'],
                'email' => strtolower(trim($userData['email'])),
                'password' => Hash::make($userData['password']),
            ]);

            $tokens = $this->generateTokenPair($user);

            DB::commit();

            return [
                'user' => new UserResource($user),
                'access_token' => $tokens['access_token'],
                'refresh_token' => $tokens['refresh_token'],
                'expires_in' => self::ACCESS_TOKEN_EXPIRES_IN * 60, // in seconds
            ];
        } catch (Exception $e) {
            DB::rollBack();
            throw new Exception('Registration failed: ' . $e->getMessage());
        }
    }

    public function login(string $email, string $password): array
    {
        $user = $this->user->where('email', strtolower(trim($email)))->first();

        if (!$user || !Hash::check($password, $user->password)) {
            throw new Exception('Invalid credentials');
        }

        $user->tokens()->delete();
        $tokens = $this->generateTokenPair($user);

        return [
            'user' => new UserResource($user),
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
            'expires_in' => self::ACCESS_TOKEN_EXPIRES_IN * 60, // in seconds
        ];
    }

    public function refreshToken(string $refreshToken): array
    {
        $userId = Cache::get("refresh_token:{$refreshToken}");

        if (!$userId) {
            throw new Exception('Invalid or expired refresh token');
        }

        $user = $this->user->find($userId);

        if (!$user) {
            throw new Exception('User not found');
        }

        // Remove old refresh token
        Cache::forget("refresh_token:{$refreshToken}");

        // Generate new token pair
        $tokens = $this->generateTokenPair($user);

        return [
            'user' => new UserResource($user),
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
            'expires_in' => self::ACCESS_TOKEN_EXPIRES_IN * 60, // in seconds
        ];
    }

    private function generateTokenPair(User $user): array
    {
        $accessToken = $user->createToken(
            'access-token',
            ['*'],
            Carbon::now()->addMinutes(self::ACCESS_TOKEN_EXPIRES_IN)
        )->plainTextToken;
        $refreshToken = bin2hex(random_bytes(32));
        $refreshTokenKey = "refresh_token:{$refreshToken}";

        Cache::put($refreshTokenKey, $user->id, Carbon::now()->addDays(self::REFRESH_TOKEN_EXPIRES_IN));

        $userRefreshTokens = Cache::get("user_refresh_tokens:{$user->id}", []);
        $userRefreshTokens[] = $refreshTokenKey;
        Cache::put(
            "user_refresh_tokens:{$user->id}",
            $userRefreshTokens,
            Carbon::now()->addDays(self::REFRESH_TOKEN_EXPIRES_IN)
        );

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken
        ];
    }

    public function logout(User $user, string $refreshToken = null): void
    {
        $user->currentAccessToken()->delete();

        if ($refreshToken) {
            Cache::forget("refresh_token:{$refreshToken}");
        }
    }

    public function logoutAll(User $user): void
    {
        $user->tokens()->delete();

        // Remove all refresh tokens for this user
        $cacheKeys = Cache::get("user_refresh_tokens:{$user->id}", []);

        foreach ($cacheKeys as $cacheKey) {
            Cache::forget($cacheKey);
        }
        Cache::forget("user_refresh_tokens:{$user->id}");
    }

    public function providerRegistration(object $userData): array
    {
        $this->validateProvider($userData->provider);

        $existing = $this->user
        ->where('email', $userData->email)
        ->orWhereHas('providers', function ($q) use ($userData) {
            $q->where('provider', $userData->provider)
              ->where('provider_id', $userData->provider_id);
        })
        ->first();

        if ($existing) {
            throw new Exception('User already exists', 409);
        }

        return \DB::transaction(function () use ($userData) {
            $user = $this->user->firstOrCreate(
                ['email' => $userData->email],
                [
                    'name'              => $userData->name,
                    'email_verified_at' => Carbon::now(),
                ]
            );

            $user->providers()->updateOrCreate(
                [
                    'provider'    => $userData->provider,
                    'provider_id' => $userData->provider_id,
                ],
                [
                    'avatar' => $userData->avatar,
                ]
            );

            $tokens = $this->generateTokenPair($user);

            return [
                'user'          => $user->fresh(['providers']),
                'access_token'  => $tokens['access_token'],
                'refresh_token' => $tokens['refresh_token'],
                'expires_in'    => self::ACCESS_TOKEN_EXPIRES_IN * 60,
            ];
        });
    }

    protected function validateProvider($provider)
    {
        $allowed = ['github', 'google'];

        if (!in_array($provider, $allowed, true)) {
            throw new Exception("Provider '{$provider}' is not supported.", 422);
        }
    }
}