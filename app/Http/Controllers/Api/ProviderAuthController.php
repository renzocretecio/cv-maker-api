<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use App\Services\AuthService;
use App\Models\User;
use App\Services\ApiResponseService;

class ProviderAuthController extends Controller
{
    protected AuthService $authService;
    protected $user;

    public function __construct(AuthService $authService, User $user)
    {
        $this->authService = $authService;
        $this->user = $user;
    }

    public function redirectToProvider($provider)
    {
        $validated = $this->validateProvider($provider);

        if (!us_null($validated)) {
            return $validated;
        }

        return Socialite::driver($provider)->stateless()->redirect();
    }

    public function handleProviderCallback($provider)
    {
        $validated = $this->validateProvider($provider);

        if (!us_null($validated)) {
            return $validated;
        }

        try {
            $providerUser = Socialite::driver($provider)->stateless()->user();
        } catch (Exception $e) {
            return ApiResponseService::error(
                'Invalid credentials',
                null,
                422
            );
        }

        $userCreated = $this->user->firstOrCreate(
            [
                'email' => $providerUser->getEmail()
            ],
            [
                'email_verified_at' => now(),
                'name' => $providerUser->getName(),
                'status' => true,
            ]
            );
        $userCreated->providers()->updateOrCreate(
            [
                'provider' => $provider,
                'provider_id' => $providerUser->getId(),
            ],
            [
                'avatar' => $providerUser->getAvatar()
            ]
        );
        $tokens = $this->authService($userCreated);

        return ApiResponseService::success([
            'user' => $userCreated,
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
            'expires_in' => self::ACCESS_TOKEN_EXPIRES_IN * 60, // in seconds
        ], 'Login successful');
    }

    protected function validateProvider($provider)
    {
        if (!in_array($provider, ['github', 'google'])) {
            return ApiResponseService::error('Login failed');
        }
    }
}
