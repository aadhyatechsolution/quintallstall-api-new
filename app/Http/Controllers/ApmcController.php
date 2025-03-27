<?php

namespace App\Http\Controllers;

use App\Models\Apmc;
use Illuminate\Http\Request;

class ApmcController extends Controller
{
    // Get all apmc records
    public function index()
    {
        return response()->json(Apmc::all());
    }

    // Create a new apmc record
    public function store(Request $request)
    {
        // Validate the incoming data
        $request->validate([
            'name' => 'required|string|max:255',
            'location' => 'required|string|max:255',
            'area' => 'required|string|max:255',
        ]);

        // Create and save the new record
        $apmc = Apmc::create($request->all());

        return response()->json($apmc, 201); // Return the created record
    }

    // Get a specific apmc record by ID
    public function show($id)
    {
        $apmc = Apmc::findOrFail($id);
        return response()->json($apmc);
    }

    // Update an apmc record
    public function update(Request $request, $id)
    {
        $apmc = Apmc::findOrFail($id);

        // Validate the incoming data
        $request->validate([
            'name' => 'required|string|max:255',
            'location' => 'required|string|max:255',
            'area' => 'required|string|max:255',
        ]);

        // Update the record
        $apmc->update($request->all());

        return response()->json($apmc);
    }

    // Delete an apmc record
    public function destroy($id)
    {
        $apmc = Apmc::findOrFail($id);
        $apmc->delete();
        return response()->json(null, 204); // Return no content status
    }
}
