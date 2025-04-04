<?php

// app/Http/Controllers/ProductController.php

namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;

class ProductController extends Controller
{
    // Method to create a new product
    public function create(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'category' => 'required|string|max:255',
            'description' => 'required|string',
            'image' => 'nullable|string', // Or 'image' => 'nullable|image' for validating image files
        ]);

        // Create the product using the validated data
        $product = Product::create([
            'name' => $request->name,
            'category' => $request->category,
            'description' => $request->description,
            'image' => $request->image, // Save the image URL or file path
        ]);

        return response()->json(['product' => $product], 201);
    }

    // Method to get all products
    public function index()
    {
        $products = Product::all(); // Get all products
        return response()->json(['products' => $products], 200);
    }

    // Method to show a single product by ID
    public function show($id)
    {
        $product = Product::findOrFail($id); // Find product by ID
        return response()->json(['product' => $product], 200);
    }

    // Method to update a product by ID
    public function update(Request $request, $id)
    {
        $product = Product::findOrFail($id);

        $request->validate([
            'name' => 'required|string|max:255',
            'category' => 'required|string|max:255',
            'description' => 'required|string',
            'image' => 'nullable|string',
        ]);

        $product->update([
            'name' => $request->name,
            'category' => $request->category,
            'description' => $request->description,
            'image' => $request->image,
        ]);

        return response()->json(['product' => $product], 200);
    }

    // Method to delete a product by ID
    public function destroy($id)
    {
        $product = Product::findOrFail($id);
        $product->delete();
        return response()->json(['message' => 'Product deleted successfully'], 200);
    }
}
