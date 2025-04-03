<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, HasApiTokens;
    use Notifiable;

    protected $fillable = [
        'first_name',
        'last_name',
        'business_name',
        'phone_number',
        'email',
        'password',
        'profile_image',
        'shop_number',
        'address_id',
        'apmc_id',
        'role_id',
        'bank_account_id',
    ];
    public function getJWTIdentifier()
    {
        return $this->getKey();  // Usually, this is the primary key, which is `id`
    }
    public function getJWTCustomClaims()
    {
        return [];  // You can add custom claims here if needed
    }
    public function vehicles()
    {
        return $this->hasMany(Vehicle::class);
    }
    public function address()
    {
        return $this->belongsTo(Address::class);
    }
    public function apmcs()
    {
        return $this->belongsToMany(Apmc::class, 'apmc_user', 'user_id', 'apmc_id');
    }
    public function roles()
    {
        return $this->belongsToMany(Role::class, 'role_user', 'user_id', 'role_id');
    }
    public function bankAccount()
    {
        return $this->belongsTo(BankAccount::class);
    }

}
