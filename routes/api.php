<?php

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ApmcController;
use App\Http\Controllers\RoleController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\ProductController;

use App\Http\Controllers\TestController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/
Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('auth/register', [AuthController::class, 'register']);
Route::post('auth/login', [AuthController::class, 'login']);
Route::post('auth/otpLogin', [AuthController::class, 'otpLogin']);
Route::post('auth/generateLoginOtp', [AuthController::class, 'generateLoginOtp']);

Route::post('auth/generateOtp', [AuthController::class, 'generateOtp'])->middleware(\App\Http\Middleware\CorsMiddleware::class);
Route::post('auth/verifyOtp', [AuthController::class, 'verifyOtp'])->middleware(\App\Http\Middleware\CorsMiddleware::class);
Route::middleware(['auth:api'])->get('auth/profile', [AuthController::class, 'profile']);

Route::resource('apmc', ApmcController::class);
Route::resource('role', RoleController::class);
Route::resource('products', ProductController::class);

Route::get('test', [TestController::class,'test']);
