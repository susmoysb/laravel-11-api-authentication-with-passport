<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Carbon\Carbon;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;

class AuthController extends Controller
{
    /**
     * Register a new user.
     *
     * This method handles the registration of a new user. It validates the incoming request data,
     * creates a new user record in the database, generates a access token for the user,
     * and returns the user data along with the token.
     *
     * @param \Illuminate\Http\Request $request The incoming request containing user registration data.
     *
     * @return \Illuminate\Http\JsonResponse The response containing the created user data and access token.
     *
     * @throws \Illuminate\Validation\ValidationException If the validation fails.
     * @throws \Exception If there is an error during the user creation process.
     */
    public function register(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name' => ['required', 'string', 'min:2', 'max:255'],
            'username' => ['required', 'string', 'min:2', 'max:30', Rule::unique('users')],
            'employee_id' => ['required', 'string', 'min:2', 'max:30', Rule::unique('users')],
            'email' => ['required', 'string', 'email', 'max:255', Rule::unique('users')],
            'password' => ['required', 'string', 'min:8', 'confirmed'],
        ]);

        $validatedData = $validator->validated();

        try {
            DB::beginTransaction();
            $user = User::create($validatedData);

            // Create a new access token
            $tokenResult = $user->createToken('auth_token');

            DB::commit();

            return self::withCreated(
                'User ' . self::MESSAGES['register'],
                [
                    'user' => $user,
                    'token' => $tokenResult->accessToken,
                    'token_type' => 'Bearer',
                    'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString(),
                ]
            );
        } catch (Exception $e) {
            DB::rollBack();
            return self::withBadRequest(self::MESSAGES['system_error'], $e->getMessage() . ' ' . get_class($e));
        }
    }

    /**
     * Handle the login request.
     *
     * This method validates the login credentials provided in the request.
     * It accepts a 'login' field which can be a username, employee_id, or email, and a 'password' field
     * If the credentials are valid, it generates a new access token for the user and returns it along with user data.
     * If the credentials are invalid, it returns an unauthorized response.
     *
     * @param \Illuminate\Http\Request $request The incoming request instance.
     *
     * @return \Illuminate\Http\JsonResponse The response containing user data and access token, or an unauthorized response.
     *
     * @throws \Illuminate\Validation\ValidationException If the validation fails.
     */
    public function login(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'login' => ['required', 'string'], // Can be username, employee_id, or email
            'password' => ['required', 'string'],
        ]);

        $validatedData = $validator->validated();

        $login = $validatedData['login'];
        $password = $validatedData['password'];

        $user = User::where('username', $login)
            ->orWhere('employee_id', $login)
            ->orWhere('email', $login)
            ->first();

        if ($user && Hash::check($password, $user->password)) {

            // Create a new access token
            $tokenResult = $user->createToken('auth_token');

            return self::withOk(
                'User ' . self::MESSAGES['login'],
                [
                    'user' => $user,
                    'token' => $tokenResult->accessToken,
                    'token_type' => 'Bearer',
                    'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString(),
                ]
            );
        }

        return self::withUnauthorized(self::MESSAGES['invalid_credentials']);
    }

    /**
     * Get the login sessions for the authenticated user.
     *
     * This method retrieves all active access tokens for the authenticated user.
     * It returns the token details including the creation time, expire time
     *
     * @param \Illuminate\Http\Request $request The current request instance.
     *
     * @return \Illuminate\Http\JsonResponse The response containing the list of active login sessions.
     */
    public function loginSessions(Request $request): JsonResponse
    {
        // Retrieve tokens that are not revoked and have not expired.
        $tokens = $request->user()->tokens()
            ->where('revoked', false)
            ->where('expires_at', '>', Carbon::now())
            ->orderByDesc('created_at')
            ->get();

        return self::withOk('Active login sessions ' . self::MESSAGES['retrieve'], $tokens);
    }

    /**
     * Logout the authenticated user by revoking their access token.
     *
     * If tokenId is null, revokes the current session.
     * If tokenId is provided, revokes the specified session.
     *
     * @param \Illuminate\Http\Request $request The current request instance.
     *
     * @param int|null $tokenId The ID of the token to revoke, or null to revoke the current token.
     *
     * @return \Illuminate\Http\JsonResponse A JSON response indicating the result of the logout operation.
     */
    public function logout(Request $request, $tokenId = null): JsonResponse
    {
        // Use the current token if no token ID is provided, otherwise find the specific token
        $token = $tokenId
            ? $request->user()->tokens()->where('id', $tokenId)->where('revoked', false)->where('expires_at', '>', Carbon::now())->first()
            : $request->user()->token();

        if ($token and $token->revoke()) {
            return self::withOk('User ' . self::MESSAGES['logout']);
        }

        return self::withNotFound(self::MESSAGES['token_not_found']);
    }
}
