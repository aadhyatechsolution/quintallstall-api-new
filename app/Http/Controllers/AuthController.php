<?php
namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Role;
use App\Models\Address;
use App\Models\BankAccount;
use App\Models\Vehicle;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Auth;


class AuthController extends Controller
{
    public function register(Request $request)
    {
        // Start database transaction
        $profileImagePath = null;

        DB::beginTransaction();
        try {
            $validationRules = [
                'first_name' => 'required|string',
                'last_name' => 'required|string',
                'business_name' => 'nullable|string|required_if:role,wholeseller,retailer',
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
                'branch_name' => 'required|string',
                'vehicle_type' => 'required_if:role,delivery|string',
                'vehicle_no' => 'required_if:role,delivery|string',
                'permit_number' => 'required_if:role,delivery|string',
                'insurance_number' => 'required_if:role,delivery|string',
                'role' => 'required|string|exists:roles,slug',
            ];
            $formData = json_decode($request->input('formData'), true);

            if (in_array($formData['role'], ['wholeseller', 'retailer'])) {
                $validationRules['apmc'] = 'required|exists:apmcs,id';
            }
            $validated = validator($formData, $validationRules)->validate();
            if ($request->hasFile('profileImage')) {
                $profileImagePath = $request->file('profileImage')->store('profile_images', 'public');
            }

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
                'business_name' => $validated['business_name'] ?? null,
                'phone_number' => $validated['phone_number'],
                'email' => strtolower($validated['email']),
                'password' => Hash::make($validated['password']),
                'address_id' => $address->id,
                'bank_account_id' => $bankAccount->id,
                'vehicle_id' => null, 
                'profile_image' => $profileImagePath,
            ]);

            if ($request->role === 'delivery') {
                $vehicle = Vehicle::create([
                    'user_id' => $user->id,
                    'vehicle_type' => $validated['vehicle_type'],
                    'vehicle_no' => $validated['vehicle_no'],
                    'permit_number' => $validated['permit_number'],
                    'insurance_number' => $validated['insurance_number'],
                ]);

                
                $user->vehicle_id = $vehicle->id;
                $user->save();
            }

            $role = Role::where('slug', $validated['role'])->firstOrFail();
            $user->roles()->attach($role);

            if (in_array($validated['role'], ['wholeseller', 'retailer'])) {
                $user->apmcs()->attach($validated['apmc']);
            }

            // Commit transaction if everything succeeds
            DB::commit();
            $token = JWTAuth::fromUser($user, ['id' => $user->id]);

            return response()->json([
                'message' => 'User registered successfully',
                'success' => true,
                'accessToken' => $token,
                'user' => $user->makeHidden(['password', 'bank_account_number', 'routing_number']),
                'profile_image_url' => $profileImagePath ? asset("storage/$profileImagePath") : null,
                'roles' => $user->roles->pluck('slug'),
                'apmcs' => $user->apmcs->pluck('id'),
            ]);

        } catch (\Throwable $th) {
            // Rollback transaction on error
            DB::rollBack();
            Log::error('Registration error: ' . $th->getMessage());

            return response()->json([
                'message' => 'Registration failed: ' . $th->getMessage(),
                'error' => true
            ], 500);
        }
    }
    public function login(Request $request)
    {
        try {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required|min:6',
        ]);
    
        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $token = JWTAuth::fromUser($user, ['id' => $user->id]);
            return response()->json([
                'message' => 'Login successful',
                'accessToken' => $token,
                'user' => $user
            ]);
        }
    
        return response()->json([
            'message' => 'Invalid credentials'
        ], 401);
        } catch (\Throwable $th) {
            //throw $th;
            return $th->getMessage();
        }
    }
    public function otpLogin(Request $request){
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
        $user = User::where('phone_number', $validated['phone_number'])->first();
        if (!$user) {
            return response()->json(['error' => 'User not found.'], 404);
        }
        $token = JWTAuth::fromUser($user, ['id' => $user->id]);
        return response()->json([
            'message' => 'OTP verified successfully. Login successful.',
            'accessToken' => $token,  
            'user' => $user->makeHidden(['password', 'bank_account_number', 'routing_number']), 
        ]);
        
    }
    public function generateLoginOtp(Request $request){
        $request->validate([
            'phone_number' => 'required|digits:10', 
        ]);
        $phoneNumber = $request->phone_number;
        $otp = rand(100000, 999999);
        Cache::put('otp_' . $phoneNumber, $otp, now()->addMinutes(5));
        $this->sendOtpViaSms($phoneNumber, $otp);
        return response()->json([
            'success' => true,
        ], 200);
    }
    public function generateOtp(Request $request)
    {
        $request->validate([
            'phone_number' => 'required|digits:10', 
        ]);

        $phoneNumber = $request->phone_number;
        $email = $request->email;
        $existingPhoneNumberUser = \App\Models\User::where('phone_number', $phoneNumber)->first();
        if ($existingPhoneNumberUser) {
            return response()->json([
                'status' => 'error',
                'message' => 'Phone number is already registered.'
            ], 400);
        }
        $existingEmailUser = \App\Models\User::where('email', $email)->first();
        
        if ($existingEmailUser) {
            return response()->json([
                'status' => 'error',
                'message' => 'Email is already registered.'
            ], 400);
        }

        $otp = rand(100000, 999999);
        Cache::put('otp_' . $phoneNumber, $otp, now()->addMinutes(5));
        try {
            $this->sendOtpViaSms($phoneNumber, $otp);
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
        $curl = curl_init();

        curl_setopt_array($curl, array(
          CURLOPT_URL => 'https://www.fast2sms.com/dev/bulkV2?authorization=wdWtBiYXZ3DboP9y1p0TVRzGOajeclMrSJnQk4xL7IEKfgmUs8BudVRcxOfMT8kmv4lQrjIAXh0bsD7C&route=dlt&sender_id=QNTOTP&message=167888&variables_values='.$otp.'&flash=0&numbers='.$phoneNumber,
          CURLOPT_RETURNTRANSFER => true,
          CURLOPT_ENCODING => '',
          CURLOPT_MAXREDIRS => 10,
          CURLOPT_TIMEOUT => 0,
          CURLOPT_FOLLOWLOCATION => true,
          CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
          CURLOPT_CUSTOMREQUEST => 'GET',
          CURLOPT_HTTPHEADER => array(
            'Cookie: XSRF-TOKEN=eyJpdiI6IkRrYlwvRG1wdlwvVWRacXlMY1JiRjdIdz09IiwidmFsdWUiOiIyYTVFYm4wR3IzS2d6b1p3VnJWXC9HSHV1N3g1d1pWMWdpMU9VWmVKVXVKMW5pXC9WZVpjbXpDbDhxWGc0WHpKaGp1N0dHVVF6UWM3NWZlTEp4XC9BUjBFdz09IiwibWFjIjoiMmJkZjlhMzU0MmNhMzQ3ZmU1NDFlM2U1N2MyMzAyYzczZTQ4MmQ2NzVjMzdmMTVlZDFhNmMxYjgwYzcxMzE4MSJ9; laravel_session=eyJpdiI6ImF5SU1QMUdWWkw2a3RvdXhQc3psWnc9PSIsInZhbHVlIjoiZm8ralZvZ3E3VzhqMmtJSlJBYlpjbjgyYVh3ZUhzUWRcL25JTWpmeXNJTGJrK2dHV1wvQmdSelFWUXc3T2hId3Z6R3JxdzJBazRZbERLbmhCY1NXZVptZz09IiwibWFjIjoiYzkxNmE0ODBkN2U1ZTZiZWYzMjEyMWFhNmJiYzEwYjFkZGM4YTZhYWUyZmQzYmJjYWIxZDdjYjU5MTVmZTE0YSJ9; oHx06S1gLorY9m72dkq2ujUIL6VULhiQm910LUir=eyJpdiI6IjBwOENYcnNBb2dpVjU0WGFjWUd3aFE9PSIsInZhbHVlIjoiUE41Q2p6SEV4VVwvOUpzd3J4WGVmSFpJWHZpMnpQb3NUQ0NPUDdyeUt2c0VHUDR6eFJRXC90Wk1cLzhsTlZVaVVBZ1dOaDNuQll5cEs1ZFRcL0VENWlCQ1YzXC8zVWZFTVQxSUxac2I5OElTZ3VFMDJUcExnU3Z4ZUdvdXpTdlZGNE0yU2NPM0pEVFROVDFYVmpCd0VLWDJlelpJS1RIeXpESE5ZRndHU3ZISUg3RWFcL3YrRFVDOGNKSTZZcHpXVXhcL2F0NFJqTmo2WldkcVdsM21vXC9ONmNpOXhSNkVHTHJLRVlIdTVpNlBtRTFRZTRsNjZsaFU0eTFSR25LbGJhSjNlcUREdytMQVJ0c0pCWUcrSGkyTWQ0ZDlHazNGelhwQ21yeVwvMlNPaDRyNDlnbVFvcDZneVwvdnBOUTdhT1hPU095dE5vSURod1FxTFZ1bTUzR1d6bFR1d1hIK2pYS3lVOWZxWEhzSmM5MVRtbWIxemI1SXNxOHl3d0dHY2FIanpDbnpVTFE3THF5YUhjV0xGVWZHK2ZNeFJzOHZqYnRiVlJ6bW54bk5QOG9TaFpKWlp2WXR2NVY0WVNvTUhKOXFEaGZsRUNtN01oVWJWTmRvSHlFOExTTllSRDcxcEFsUERsTTA4S0prSlV2OWg3U09RdnFJNGw5MkN0dW9xS3pFQjMzM01EVVwvSnpGQ3hCN0NRTys0ajBXbEUxRHhZbDhcL0lyejNVSm5MQzhLcVwvRFZ4ST0iLCJtYWMiOiJiYTBiZjZlNDY3ZmViYWE3OGYwNTU1NTExMmY4ZTg4ZGIyNjg3ZGY0NDQ0YTAzYjRiZmFlODdmMmFmNDRjYTNkIn0%3D'
          ),
        ));
        
        $response = curl_exec($curl);
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
            'success' => true
        ,]);
    }
    public function profile(Request $request)
    {
        $user = Auth::user();
        return response()->json([
            'user' => $user,
        ]);
    }
}
