<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Role;

class RoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run()
    {
        Role::create([
            'name' => 'Admin',
            'slug' => 'admin',
            'description' => 'Administrator role',
        ]);

        Role::create([
            'name' => 'User',
            'slug' => 'user',
            'description' => 'Regular user role',
        ]);
    }
}
