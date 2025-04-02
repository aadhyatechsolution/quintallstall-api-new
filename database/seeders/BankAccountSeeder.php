<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\BankAccount;

class BankAccountSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run()
    {
        BankAccount::create([
            'account_number' => '1234567890',
            'ifsc_code' => 'IFSC1234',
            'account_type' => 'Saving',
            'branch_name' => 'Branch One',
        ]);

        // Add more bank accounts as needed
    }
}
