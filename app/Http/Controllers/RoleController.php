<?php
namespace App\Http\Controllers;

use App\Models\Role;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class RoleController extends Controller
{
    public function index()
    {
        return response()->json(Role::all());
    }

    public function store(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255|unique:roles,name',  // Ensure role name is unique
            'slug' => 'required|string|max:255|unique:roles,slug',  // Ensure slug is unique
        ]);

        $role = Role::create([
            'name' => $request->name,
            'slug' => $request->slug,
        ]);

        return response()->json($role, 201);
    }

    public function show($id)
    {
        $role = Role::findOrFail($id);
        return response()->json($role);
    }

    public function update(Request $request, $id)
    {
        $role = Role::findOrFail($id);
        $request->validate([
            'name' => 'required|string|max:255|unique:roles,name,' . $role->id,  // Ensure unique name excluding the current role
            'slug' => 'required|string|max:255|unique:roles,slug,' . $role->id,  // Ensure unique slug excluding the current role
        ]);
        $role->update([
            'name' => $request->name,
            'slug' => $request->slug,
        ]);        
        return response()->json($role);
    }

    public function destroy($id)
    {
        $role = Role::findOrFail($id);
        $role->delete();
        return response()->json(null, 204);
    }
}
