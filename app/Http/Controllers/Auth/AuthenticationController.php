<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\AuthenticationLoginRequest;
use App\Http\Requests\AuthenticationRegisterRequest;
use App\User;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Token;

class AuthenticationController extends Controller
{

    /**
     * Login user
     *
     * @param AuthenticationLoginRequest $request
     * @return JsonResponse
     */
    public function loginUser(AuthenticationLoginRequest $request)
    {
        $email = $request->get('email');
        $password = $request->get('password');
        $credentials = [$email, $password];
        // Attempt auth
        if (!Auth::attempt($credentials)) {
            return response()->json(['message' => 'Not authorized!'], 401);
        }
        /** @var User $user */
        $user = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');
        /** @var Token $token */
        $token = $tokenResult->token;

        if ($request->get('remember_me')) {
            $token->expires_at = Carbon::now()->addWeeks(1);
        }
        $token->save();

        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString()
        ]);
    }

    /**
     * Register user
     *
     * @param AuthenticationRegisterRequest $request
     * @return JsonResponse
     */
    public function registerUser(AuthenticationRegisterRequest $request)
    {
        $user = new User();
        $user->name = $request->get('name');
        $user->email = $request->get('email');
        $user->password = bcrypt($request->get('password'));

        $user->save();

        return response()->json([
            'message' => 'User created successfully!'
        ], 201);

    }

    /**
     * Logout user
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function logoutUser(Request $request)
    {
        $request->user()->token()->revoke();

        return response()->json([
            'message' => 'User logged out successfully!'
        ]);
    }

    /**
     * Get authenticated user
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function getAuthenticatedUser(Request $request)
    {
        $user = $request->user();

        return response()->json($user);
    }
}
