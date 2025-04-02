<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BankAccount extends Model
{
    use HasFactory;

    // Define the fillable attributes
    protected $fillable = [
        'account_number',
        'ifsc_code',
        'account_type',
        'branch_name',
    ];

    // Define the relationship
    public function users()
    {
        return $this->hasMany(User::class);
    }
}
