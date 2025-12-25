#!/bin/bash
# Comprehensive secp256k1 UCRT64 compilation script with JNI support

set -e  # Exit on error

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Project root: $PROJECT_ROOT"

echo "Step 1: Ensure we're in the secp256k1 source directory"
if [ ! -f "./configure.ac" ] && [ ! -f "./CMakeLists.txt" ]; then
    echo "Error: This script must be run from the secp256k1 source directory"
    exit 1
fi

echo "Step 2: Configure and build secp256k1 with UCRT64 toolchain"
# Create a build directory specifically for UCRT64 
mkdir -p build_ucrt64_jni
cd build_ucrt64_jni

# If autotools is available, use that, otherwise try cmake
if [ -f "../configure" ]; then
    echo "Using autotools to build secp256k1 with JNI support..."
    ../configure --enable-jni --enable-experimental --enable-module-recovery --enable-module-ecdh --host=x86_64-w64-mingw32
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    echo "secp256k1 build completed with autotools"
elif [ -f "../CMakeLists.txt" ]; then
    echo "Using CMake to build secp256k1 with JNI support..."
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../../toolchain-ucrt64.cmake -DENABLE_JNI=ON -DENABLE_EXPERIMENTAL=ON -DENABLE_MODULE_RECOVERY=ON -DENABLE_MODULE_ECDH=ON
    cmake --build . --parallel
    echo "secp256k1 build completed with CMake"
else
    # Auto-generate configure script and build
    echo "Generating configure script and building..."
    autoreconf -ivf ..
    cd ..
    ./configure --enable-jni --enable-experimental --enable-module-recovery --enable-module-ecdh --host=x86_64-w64-mingw32
    make -j4
    cd build_ucrt64_jni  # Go back to build directory
fi

echo "Step 3: Verify that the secp256k1 library was built successfully"
if [ -f "libsecp256k1.la" ] || [ -f ".libs/libsecp256k1-0.dll" ] || [ -f "msys-secp256k1-6.dll" ]; then
    echo "secp256k1 library build successful"
    # Find the built DLL
    DLL_FILE=$(find . -name "*.dll" -type f | head -n 1)
    if [ -n "$DLL_FILE" ]; then
        echo "Found built DLL: $DLL_FILE"
        cp "$DLL_FILE" "$PROJECT_ROOT/"
        echo "Copied DLL to project root"
    fi
else
    echo "Error: Could not find built secp256k1 library"
    exit 1
fi

echo "Step 4: Compile the JNI wrapper"
cd "$PROJECT_ROOT"

# Make sure we have the JNI header file
if [ ! -f "org_libsecp256k1_NativeSecp256k1.h" ]; then
    echo "Generating JNI header file..."
    javac -h . jni_secp256k1/src/main/java/org/libsecp256k1/NativeSecp256k1.java
fi

# Compile the JNI wrapper
echo "Compiling JNI wrapper..."
gcc -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/win32" -I./include -I. -shared -fPIC -o jni_secp256k1_wrapper.dll jni_native_impl.c -L. -l:$(basename $(find . -name "libsecp256k1*.dll" -o -name "msys-secp256k1*.dll" | head -n 1)) -Wl,--kill-at

if [ $? -eq 0 ]; then
    echo "JNI wrapper compiled successfully: jni_secp256k1_wrapper.dll"
    
    # Copy the wrapper DLL to the Java project
    cp jni_secp256k1_wrapper.dll jni_secp256k1/src/main/resources/
    cp jni_secp256k1_wrapper.dll jni_secp256k1/target/ 2>/dev/null || true
    
    echo "Step 5: Run tests to verify the implementation"
    cd jni_secp256k1
    mvn test
else
    echo "Error compiling JNI wrapper"
    exit 1
fi

echo ""
echo "=== UCRT64 secp256k1 with JNI compilation complete ==="
echo "Files created:"
ls -la *.dll jni_secp256k1/*.dll jni_secp256k1/target/*.dll 2>/dev/null || echo "No DLL files found in expected locations"