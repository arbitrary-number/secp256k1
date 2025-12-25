package org.libsecp256k1;

import java.io.File;
import java.nio.file.Paths;

/**
 * Utility class to help locate and load the secp256k1 native library
 * from various potential system locations.
 */
public class LibraryLoader {

    /**
     * Attempts to load the secp256k1 native library from various locations
     */
    public static boolean loadSecp256k1Library() {
        // FIRST: Try our compiled JNI wrapper DLL that contains both secp256k1 and JNI functions
        String ourCompiledDllPath = System.getProperty("user.dir") + "/target/secp256k1_jni.dll";
        File ourCompiledDllFile = new File(ourCompiledDllPath);
        if (ourCompiledDllFile.exists()) {
            try {
                System.load(ourCompiledDllFile.getAbsolutePath());
                System.out.println("Successfully loaded secp256k1 JNI wrapper library from: " + ourCompiledDllPath);
                System.out.println("Library contains combined secp256k1 and JNI function implementations");
                return true;
            } catch (UnsatisfiedLinkError e) {
                System.out.println("Could not load from our compiled JNI wrapper: " + ourCompiledDllPath + " - " + e.getMessage());
            }
        }
        
        // SECOND: Try the copy we made with the expected name (msys-secp256k1-6.dll)
        String expectedDllPath = System.getProperty("user.dir") + "/target/msys-secp256k1-6.dll";
        File expectedDllFile = new File(expectedDllPath);
        if (expectedDllFile.exists()) {
            try {
                System.load(expectedDllFile.getAbsolutePath());
                System.out.println("Successfully loaded secp256k1 JNI wrapper library from: " + expectedDllPath);
                System.out.println("Library contains combined secp256k1 and JNI function implementations");
                return true;
            } catch (UnsatisfiedLinkError e) {
                System.out.println("Could not load from expected location: " + expectedDllPath + " - " + e.getMessage());
            }
        }

        // Third, try loading with System.load from specific file paths in a comprehensive way

        // Define possible file names for the secp256k1 library
        String[] possibleNames = {
            "msys-secp256k1-6.dll",
            "libsecp256k1-0.dll",
            "secp256k1.dll",
            "msys-secp256k1.dll"
        };

        // Define possible search paths
        String[] possiblePaths = {
            // Direct paths to known build locations
            System.getProperty("user.dir") + "/../build/bin",
            System.getProperty("user.dir") + "/../build_ucrt64/bin",
            System.getProperty("user.dir") + "/build/bin",
            System.getProperty("user.dir") + "/build_ucrt64/bin",

            // Project root and common locations
            System.getProperty("user.dir"),
            System.getProperty("user.dir") + "/lib",
            System.getProperty("user.dir") + "/native",
            System.getProperty("user.dir") + "/bin",
            System.getProperty("user.dir") + "/target",

            // Common MSYS2 locations
            "C:/msys64/ucrt64/bin",
            "C:/msys64/mingw64/bin",

            // Windows system directories
            System.getenv("WINDIR") + "/System32",
            System.getenv("WINDIR") + "/SysWOW64"
        };

        // Try each combination of path + name
        for (String path : possiblePaths) {
            for (String name : possibleNames) {
                try {
                    String fullPath = path + "/" + name;
                    File dllFile = new File(fullPath);

                    if (dllFile.exists()) {
                        System.load(dllFile.getAbsolutePath());
                        System.out.println("Successfully loaded secp256k1 library from: " + fullPath);

                        // At this point, the library is loaded into the JVM,
                        // but we can't fully verify the functions without triggering the static initialization
                        // which would cause a recursive call. So we just return true here.
                        System.out.println("Library load successful - native functions should be available");
                        return true;
                    }
                } catch (UnsatisfiedLinkError e) {
                    System.out.println("Failed to load from: " + path + "/" + name + " - " + e.getMessage());
                    // Continue to try other combinations
                }
            }
        }

        // Then, try to load from system library path using System.loadLibrary
        String[] potentialNames = {
            "msys-secp256k1-6",
            "libsecp256k1-0",
            "secp256k1"
        };

        for (String name : potentialNames) {
            try {
                System.loadLibrary(name);
                System.out.println("Successfully loaded secp256k1 library: " + name);
                return true;
            } catch (UnsatisfiedLinkError e) {
                System.out.println("Could not load library: " + name + " - " + e.getMessage());
            }
        }

        System.err.println("Could not find or load secp256k1 native library from any known location.");
        System.err.println("Library loading will fail - ensure UCRT64-compiled secp256k1 library is available.");
        return false;
    }
}