<?php
namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Role;
use App\Models\Address;
use App\Models\BankAccount;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;


class AuthController extends Controller
{
    public function register(Request $request)
    {   
        try {
            $validated = $request->validate([
                'first_name' => 'required|string',
                'last_name' => 'required|string',
                'business_name' => 'required|string',
                'street' => 'required|string', 
                'phone_number' => 'required|string|unique:users',
                'email' => 'required|email|unique:users',
                'password' => 'required|min:6|confirmed',
                'bank_account_number' => 'required|string', 
                'city' => 'required|string', 
                'state' => 'required|string', 
                'postal_code' => 'required|string', 
                'routing_number' => 'required|string', 
                'shop_number' => 'required|string', 
                'ifsc_code' => 'required|string',
                'account_type' => 'required|string',
                'branch_name' => 'required|string'
            ]);
            // Create an address record first
            $address = Address::create([
                'street' => $validated['street'],
                'city' => $validated['city'],
                'state' => $validated['state'],
                'postal_code' => $validated['postal_code'],
                'shop_number' => $validated['shop_number'],
            ]);
            $bankAccount = BankAccount::create([
                'account_number' => Crypt::encryptString($validated['bank_account_number']),
                'routing_number' => Crypt::encryptString($validated['routing_number']),
                'ifsc_code' => $validated['ifsc_code'],
                'account_type' => $validated['account_type'],
                'branch_name' => $validated['branch_name']
            ]);
            $user = User::create([
                'first_name' => $validated['first_name'],
                'last_name' => $validated['last_name'],
                'business_name' => $validated['business_name'],
                'phone_number' => $validated['phone_number'], 
                'email' => strtolower($validated['email']),
                'password' => Hash::make($validated['password']),
                'address_id' => $address->id, 
                'bank_account_id' => $bankAccount->id,
            ]);

            $role = Role::find(1);
            $user->roles()->attach($role);

            return response()->json([
                'message' => 'User registered successfully',
                'success' => true,
                'user' => $user->makeHidden(['password', 'bank_account_number', 'routing_number']) 
            ]);
        } catch (\Throwable $th) {
            return response()->json([
                'message' => $th->getMessage(),
                'error' => true
            ]);
        }
    }
    
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
