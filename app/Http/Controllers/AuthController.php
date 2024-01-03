<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Auth;
use Illuminate\Support\Facades\Auth as FacadesAuth;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }
    public function register(Request $req)
    {
        $validator = validator($req->all(), [
            'name' => 'required',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed|min:6'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($req->password)]
        ));

        return response()->json([
            'status' => true,
            'error' => '',
            'data' => $user
        ], 201);
    }


    public function login(Request $req)
    {
        $validator = validator($req->all(), [
            'email' => 'required|email',
            'password' => 'required|string'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        // if (!$token = auth('api')->÷attempt($validator->validated())) {
        if (!$token = FacadesAuth::attempt([
            'email' => $req->email,
            'password' => $req->password
        ])) {
            return response()->json([
                'status' => false,
                'error' => 'Unauthorized',
                'data' => null
            ], 401);
        }
        return $this->createNewToken($token);
    }

    public function createNewToken($token)
    {
        return response()->json([
            'user' => auth()->user(),
            'expires_in' => config('auth.guards.api.expire') * 60,
            'access_token' => $token,
            'token_type' => 'bearer',
        ], 200);
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => FacadesAuth::user(),
            'authorisation' => [
                'refresh_token' => FacadesAuth::refresh(),
                'type' => 'bearer',
            ]
        ]);
    }

    public function user()
    {
        $user = auth('api')->user();

        return response()->json([
            'status' => true,
            'error' => '',
            'data' => $user,
        ]);
    }
}
