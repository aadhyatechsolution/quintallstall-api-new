<?php

namespace Database\Seeders;

use App\Models\Apmc;
use Illuminate\Database\Seeder;

class ApmcSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // Array of data you want to seed into the apmc table
        $data = [
            ['name' => 'John Doe', 'location' => 'New York', 'area' => 'Finance'],
            ['name' => 'Kessy Bryan', 'location' => 'San Francisco', 'area' => 'Tech'],
            ['name' => 'James Cassegne', 'location' => 'Los Angeles', 'area' => 'Engineering'],
            ['name' => 'John Doe', 'location' => 'New York', 'area' => 'Finance'],
            ['name' => 'Kessy Bryan', 'location' => 'San Francisco', 'area' => 'Tech'],
            ['name' => 'James Cassegne', 'location' => 'Los Angeles', 'area' => 'Engineering'],
            ['name' => 'John Doe', 'location' => 'New York', 'area' => 'Finance'],
            ['name' => 'Kessy Bryan', 'location' => 'San Francisco', 'area' => 'Tech'],
            ['name' => 'James Cassegne', 'location' => 'Los Angeles', 'area' => 'Engineering'],
            ['name' => 'John Doe', 'location' => 'New York', 'area' => 'Finance'],
            ['name' => 'Kessy Bryan', 'location' => 'San Francisco', 'area' => 'Tech'],
            ['name' => 'James Cassegne', 'location' => 'Los Angeles', 'area' => 'Engineering'],
        ];

        // Insert the data into the apmc table
        foreach ($data as $apmcData) {
            Apmc::create($apmcData);
        }
    }
}
