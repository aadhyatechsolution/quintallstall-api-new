<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    use HasFactory, HasApiTokens;
    
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

    // Define the relationships

    // A user can belong to one address
    public function address()
    {
        return $this->belongsTo(Address::class);
    }

    // A user can belong to one apmc
    public function apmc()
    {
        return $this->belongsTo(Apmc::class);
    }

    // A user can have one role
    public function roles()
    {
        return $this->belongsToMany(Role::class, 'role_user', 'user_id', 'role_id');
    }

    // A user can have one bank account
    public function bankAccount()
    {
        return $this->belongsTo(BankAccount::class);
    }

}
