<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Address extends Model
{
    use HasFactory;

    // Define the fillable attributes
    protected $fillable = [
        'street',
        'city',
        'state',
        'zipcode',
    ];

    // Define the relationship
    public function users()
    {
        return $this->hasMany(User::class);
    }
}
