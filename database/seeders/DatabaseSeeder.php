<?php

namespace Database\Seeders;

use App\Models\User;
// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        User::factory()->create([
            'name' => 'Super Admin',
            'username' => 'super_admin',
            'employee_id' => 'SA001',
            'email' => 'superadmin@example.com',
        ]);
        User::factory()->create([
            'name' => 'Admin',
            'username' => 'admin',
            'employee_id' => 'A001',
            'email' => 'admin@example.com',
        ]);
        User::factory(100)->create();
    }
}
