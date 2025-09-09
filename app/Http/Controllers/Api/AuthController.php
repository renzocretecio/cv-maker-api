<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use App\Services\AuthService;
use App\Services\ApiResponseService;
use Illuminate\Http\JsonResponse;
use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\RefreshTokenRequest;
use Exception;

class AuthController extends Controller
{
    protected AuthService $authService;

    public function __construct(AuthService $authService)
    {
        $this->authService = $authService;
    }

    public function register(RegisterRequest $request): JsonResponse
    {
        try {
            $result = $this->authService->register($request->validated());

            return ApiResponseService::created([
                'user' => $result['user'],
                'access_token' => $result['access_token'],
                'refresh_token' => $result['refresh_token'],
                'token_type' => 'Bearer',
                'expires_in' => $result['expires_in'],
            ], 'User registered succesfully');
        } catch (Exception $e) {
            return ApiResponseService::error(
                'Registration failed: ' . $e->getMessage(),
                null,
                500
            );
        }
    }

    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        try {
            $result = $this->authService->login($request->email, $request->password);

            return ApiResponseService::success([
                'user' => $result['user'],
                'access_token' => $result['access_token'],
                'refresh_token' => $result['refresh_token'],
                'token_type' => 'Bearer',
                'expires_in' => $result['expires_in'],
            ], 'Login successful');

        } catch (Exception $e) {
            return ApiResponseService::unauthorized($e->getMessage());
        }
    }

    public function refresh(RefreshTokenRequest $request): JsonResponse
    {
        try {
            $result = $this->authService->refreshToken($request->refresh_token);

            return ApiResponseService::success([
                'user' => $result['user'],
                'access_token' => $result['access_token'],
                'refresh_token' => $result['refresh_token'],
                'token_type' => 'Bearer',
                'expires_in' => $result['expires_in'],
            ], 'Token refreshed successfully');

        } catch (Exception $e) {
            return ApiResponseService::unauthorized($e->getMessage());
        }
    }

    /**
     * Logout user (revoke current token and refresh token)
     */
    public function logout(Request $request): JsonResponse
    {
        $request->validate([
            'refresh_token' => ['sometimes', 'string']
        ]);

        try {
            $this->authService->logout(
                $request->user(),
                $request->refresh_token
            );

            return ApiResponseService::success(
                null,
                'Logged out successfully'
            );

        } catch (Exception $e) {
            return ApiResponseService::error('Logout failed');
        }
    }

    /**
     * Logout from all devices
     */
    public function logoutAll(Request $request): JsonResponse
    {
        try {
            $this->authService->logoutAll($request->user());

            return ApiResponseService::success(
                null,
                'Logged out from all devices successfully'
            );

        } catch (Exception $e) {
            return ApiResponseService::error('Logout failed');
        }
    }

    /**
     * Get authenticated user
     */
    public function me(Request $request): JsonResponse
    {
        return ApiResponseService::success(
            new \App\Http\Resources\UserResource($request->user()),
            'User profile retrieved successfully'
        );
    }
}
