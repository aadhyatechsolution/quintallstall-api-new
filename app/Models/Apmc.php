<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Apmc extends Model
{
    use HasFactory;
    protected $fillable = ['name', 'location', 'area', 'file'];

    public function users()
    {
        return $this->hasMany(User::class);
    }
}
