<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Vehicle extends Model
{
    protected $fillable = [
        'user_id', 'vehicle_type', 'vehicle_no', 'permit_number', 'insurance_number'
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
