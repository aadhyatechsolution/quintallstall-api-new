<?php
namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Role;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

class AuthController extends Controller
{
    // Register User
    public function register(Request $request)
    {
        
        // Validate the incoming request
        
        $validated = $request->validate([
            'first_name' => 'required|string',
            'last_name' => 'required|string',
            'business_name' => 'required|string',
            'phone_number' => 'required|string|unique:users',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6|confirmed', // Ensure 'password_confirmation' is sent in request
        ]);
        
        // Create user and hash the password
        $user = User::create([
            'first_name' => $validated['first_name'],
            'last_name' => $validated['last_name'],
            'business_name' => $validated['business_name'],
            'phone_number' => $validated['phone_number'], 
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        // Assign the default role (assuming role with ID 1 exists)
        $role = Role::find(1);  // Replace with dynamic role assignment if needed
        $user->roles()->attach($role);
        
        // Return response with success message and user data
        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user
        ]);
    }

    // Login User and return token
    public function login(Request $request)
    {
        // Validate login request
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // Attempt to log the user in
        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            // Generate Sanctum token
            $token = $user->createToken('YourAppName')->plainTextToken;

            return response()->json([
                'message' => 'Login successful',
                'token' => $token
            ]);
        }

        // If authentication fails
        return response()->json([
            'message' => 'Invalid credentials'
        ], 401);
    }

    public function generateOtp(Request $request)
    {
        $request->validate([
            'phone_number' => 'required|digits:10', 
        ]);

        $phoneNumber = $request->phone_number;
        $existingUser = \App\Models\User::where('phone_number', $phoneNumber)->first();

        if ($existingUser) {
            return response()->json([
                'status' => 'error',
                'message' => 'Phone number is already registered.'
            ], 400); // Return an error if the phone number is already registered
        }

        $otp = rand(100000, 999999);
        Cache::put('otp_' . $phoneNumber, $otp, now()->addMinutes(5));
        try {
            // $this->sendOtpViaSms($phoneNumber, $otp);
            return response()->json([
                'status' => 'success',
                'message' => 'OTP sent successfully.',
                'otp' => $otp
            ]);
        } catch (\Exception $e) {
            Log::error('OTP Sending Failed: ' . $e->getMessage());
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to send OTP.'
            ], 500);
        }
    }
    private function sendOtpViaSms($phoneNumber, $otp)
    {
        $sid = env('TWILIO_SID');
        $token = env('TWILIO_AUTH_TOKEN');
        $from = env('TWILIO_PHONE_NUMBER');

        $client = new Client($sid, $token);
        $client->messages->create(
            $phoneNumber,
            [
                'from' => $from,
                'body' => "Your OTP is: " . $otp
            ]
        );
    }
    public function verifyOtp(Request $request)
    {
        $validated = $request->validate([
            'phone_number' => 'required|string|size:10',
            'otp' => 'required|string|size:6',
        ]);
        $cachedOtp = Cache::get('otp_' . $validated['phone_number']);
        if (!$cachedOtp) {
            return response()->json(['error' => 'OTP is invalid or has expired.'], 400);
        }

        if ($cachedOtp != $validated['otp']) {
            return response()->json(['error' => 'Invalid OTP.'], 400);
        }

        Cache::forget('otp_' . $validated['phone_number']);

        return response()->json([
            'error' => false,
            'message' => 'OTP verified successfully.',
            'status' => 'success'
        ,]);
    }
}
