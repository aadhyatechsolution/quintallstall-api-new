<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Address;

class AddressSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run()
    {
        Address::create([
            'street' => '123 Main Street',
            'city' => 'Cityville',
            'state' => 'State',
            'postal_code' => '123456',
        ]);

        // Add more addresses as needed
    }
}
