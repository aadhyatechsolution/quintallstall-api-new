<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Apmc extends Model
{
    use HasFactory;
    // Table name is 'apmc' (Laravel automatically uses plural table names but we specify it manually)
    protected $table = 'apmc';

    // Define the fillable columns
    protected $fillable = ['name', 'location', 'area'];
}
