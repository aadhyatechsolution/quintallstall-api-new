<?php

namespace Database\Seeders;

use App\Models\Apmc;
use App\Models\BankAccount;
use App\Models\Address;
use App\Models\Role;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $apmc = Apmc::create([
            'name' => 'John Doe', 'location' => 'New York', 'area' => 'Finance'
        ]);
        
        $bankAccount = BankAccount::create([
            'account_number' => '1234567810',
            'ifsc_code' => 'IFSC1210',
            'account_type' => 'Saving',
            'branch_name' => 'Branch two',
        ]);

        // Create some roles first
        $adminRole = Role::create([
            'name' => 'Admin',
            'slug' => 'admin',
            'description' => 'Administrator with full privileges.',
        ]);

        $userRole = Role::create([
            'name' => 'User',
            'slug' => 'user',
            'description' => 'Regular user with limited privileges.',
        ]);

        // Create some addresses
        $address = Address::create([
            'street' => '123 Main St',
            'city' => 'Springfield',
            'state' => 'Illinois',
            'postal_code' => '62701',
        ]);

        // Create users and assign them roles and addresses
        $user1 = User::create([
            'first_name' => 'John',
            'last_name' => 'Doe',
            'business_name' => 'Doe Enterprises',
            'phone_number' => '1234567890',
            'email' => 'johndoe@example.com',
            'password' => Hash::make('password123'), // Use a secure password
            'profile_image' => 'path/to/image.jpg', // Dummy image path
            'shop_number' => 'A101',
            'address_id' => $address->id,
            'apmc_id' => $apmc->id, // Assuming APMC table is already populated
        ]);

        // Assign role to user
        $user1->roles()->attach($adminRole); // Admin role

        // Create another user
        $user2 = User::create([
            'first_name' => 'Jane',
            'last_name' => 'Smith',
            'business_name' => 'Smith Consulting',
            'phone_number' => '9876543210',
            'email' => 'janesmith@example.com',
            'password' => Hash::make('password123'),
            'profile_image' => 'path/to/image2.jpg', // Dummy image path
            'shop_number' => 'B102',
            'address_id' => $address->id,
            'apmc_id' => $apmc->id, 
            'bank_account_id' => $bankAccount->id// Assuming APMC table is already populated
        ]);

        // Assign role to user
        $user2->roles()->attach($userRole); // User role

        // Add more users as needed
    }
}
