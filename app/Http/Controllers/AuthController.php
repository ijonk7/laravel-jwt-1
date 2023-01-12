<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        // 'auth:api' mendefinisikan Authentication menggunakan Guard API yaitu JWT.
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function register()
    {
        $validator = validator()->make(request()->all(), [
            'name' => 'string|required',
            'email' => 'email|required',
            'password' => 'string|min:6'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Registration Failed',
            ]);
        }

        $user = User::create([
            'name' => request()->get('name'),
            'email' => request()->get('email'),
            'password' => Hash::make(request()->get('password'))
        ]);

        // return response()->json([
        //     'message' => 'User Created!',
        //     'user' => $user
        // ]);

        if ($user) {
            return response()->json([
                'message' => 'Pendaftaran Berhasil'
            ]);
        } else {
            return response()->json([
                'message' => 'Pendaftaran Gagal'
            ]);
        }

    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        // Cara Authenticate 1
        // if (Auth::validate($credentials)) {
        //     $token = Auth::attempt($credentials);
        //     return $this->respondWithToken($token);
        // } else {
        //     return response()->json(['error' => 'Unauthorized'], 401);
        // }

        // Cara Authenticate 2
        // if (! $token = auth()->attempt($credentials)) {
        // if (! $token = JWTAuth::attempt($credentials)) {
        if (! $token = Auth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        // return response()->json(auth()->user());
        return response()->json(Auth::user());

    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        // auth()->logout();
        Auth::logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        // return $this->respondWithToken(auth()->refresh());
        return $this->respondWithToken(Auth::refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => config('jwt.ttl')
        ]);
    }
}
