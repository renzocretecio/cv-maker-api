<?php

namespace App\Services;

use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

class ApiResponseService
{
        public static function success(
        $data = null, 
        string $message = 'Success', 
        int $statusCode = Response::HTTP_OK
    ): JsonResponse {
        $response = [
            'success' => true,
            'message' => $message,
        ];

        if ($data !== null) {
            $response['data'] = $data;
        }

        return response()->json($response, $statusCode);
    }

    public static function error(
        string $message = 'An error occurred', 
        $errors = null, 
        int $statusCode = Response::HTTP_BAD_REQUEST
    ): JsonResponse {
        $response = [
            'success' => false,
            'message' => $message,
        ];

        if ($errors !== null) {
            $response['errors'] = $errors;
        }

        return response()->json($response, $statusCode);
    }

    public static function created($data, string $message = 'Resource created successfully'): JsonResponse
    {
        return self::success($data, $message, Response::HTTP_CREATED);
    }

    public static function unauthorized(string $message = 'Unauthorized'): JsonResponse
    {
        return self::error($message, null, Response::HTTP_UNAUTHORIZED);
    }

    public static function forbidden(string $message = 'Forbidden'): JsonResponse
    {
        return self::error($message, null, Response::HTTP_FORBIDDEN);
    }

    public static function notFound(string $message = 'Resource not found'): JsonResponse
    {
        return self::error($message, null, Response::HTTP_NOT_FOUND);
    }
}