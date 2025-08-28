-- premake5.lua
-- NetGuard - Modern C++ Packet Analyzer Build Configuration

workspace "NetGuard"
    architecture "x64"
    startproject "NetGuard"
    
    configurations {
        "Debug",
        "Release",
        "Profile"
    }
    
    platforms {
        "Linux",
        "Windows"
    }

    -- Global configuration
    cppdialect "C++23"
    rtti "Off"
    exceptionhandling "Off"  -- We use expected<T,E> instead
    staticruntime "On"
    
    -- Output directories
    outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"
    
    -- Include directories
    IncludeDir = {}
    IncludeDir["NetGuard"] = "include"
    IncludeDir["expected"] = "vendor/expected/include"
    IncludeDir["fmt"] = "vendor/fmt/include"
    IncludeDir["spdlog"] = "vendor/spdlog/include"
    IncludeDir["yamlcpp"] = "vendor/yaml-cpp/include"
    IncludeDir["crow"] = "vendor/crow/include"
    IncludeDir["catch2"] = "vendor/catch2/single_include"

-- Third-party dependencies
group "Dependencies"
    include "vendor/fmt"
    include "vendor/yaml-cpp"
    include "vendor/crow"

group ""

-- Main NetGuard library
project "NetGuardLib"
    location "NetGuardLib"
    kind "StaticLib"
    language "C++"
    
    targetdir ("bin/" .. outputdir .. "/%{prj.name}")
    objdir ("bin-int/" .. outputdir .. "/%{prj.name}")
    
    files {
        "include/netguard/**.hpp",
        "src/capture/**.cpp",
        "src/protocol/**.cpp", 
        "src/detection/**.cpp",
        "src/analysis/**.cpp",
        "src/ui/**.cpp",
        "src/core/logger.cpp"
    }
    
    includedirs {
        "%{IncludeDir.NetGuard}",
        "%{IncludeDir.expected}",
        "%{IncludeDir.fmt}",
        "%{IncludeDir.spdlog}",
        "%{IncludeDir.yamlcpp}",
        "%{IncludeDir.crow}"
    }
    
    links {
        "fmt",
        "yaml-cpp",
        "crow"
    }
    
    -- Platform-specific settings
    filter "system:linux"
        systemversion "latest"
        links {
            "pthread",
            "pcap"
        }
        buildoptions {
            "-Wall",
            "-Wextra", 
            "-Wpedantic",
            "-Wno-unused-parameter"
        }
        
    filter "system:windows"
        systemversion "latest"
        links {
            "ws2_32",
            "wpcap",
            "packet"
        }
        defines {
            "WIN32_LEAN_AND_MEAN",
            "_WIN32_WINNT=0x0601"  -- Windows 7+
        }
    
    -- Configuration-specific settings
    filter "configurations:Debug"
        defines {
            "NG_DEBUG",
            "NG_ENABLE_ASSERTS"
        }
        runtime "Debug"
        symbols "On"
        optimize "Off"
        sanitize { "Address", "Undefined" }
        
    filter "configurations:Release"
        defines {
            "NG_RELEASE",
            "NDEBUG"
        }
        runtime "Release"
        symbols "Off"
        optimize "Speed"
        inlining "Auto"
        vectorextensions "SSE4.1"
        
    filter "configurations:Profile"
        defines {
            "NG_PROFILE", 
            "NG_ENABLE_PROFILING"
        }
        runtime "Release"
        symbols "On"
        optimize "Speed"
        buildoptions { "-pg" }
        linkoptions { "-pg" }

-- Main NetGuard executable
project "NetGuard"
    location "NetGuard"
    kind "ConsoleApp"
    language "C++"
    
    targetdir ("bin/" .. outputdir .. "/%{prj.name}")
    objdir ("bin-int/" .. outputdir .. "/%{prj.name}")
    
    files {
        "src/core/main.cpp"
    }
    
    includedirs {
        "%{IncludeDir.NetGuard}",
        "%{IncludeDir.expected}",
        "%{IncludeDir.fmt}",
        "%{IncludeDir.spdlog}"
    }
    
    links {
        "NetGuardLib"
    }
    
    -- Platform-specific settings
    filter "system:linux"
        systemversion "latest"
        buildoptions {
            "-Wall",
            "-Wextra",
            "-Wpedantic"
        }
        
    filter "system:windows"
        systemversion "latest"
    
    -- Configuration-specific settings  
    filter "configurations:Debug"
        defines "NG_DEBUG"
        runtime "Debug"
        symbols "On"
        
    filter "configurations:Release"
        defines "NG_RELEASE"
        runtime "Release" 
        optimize "Speed"
        
    filter "configurations:Profile"
        defines "NG_PROFILE"
        runtime "Release"
        symbols "On"
        optimize "Speed"

-- Development tools
project "NetGuardTools"
    location "NetGuardTools"
    kind "ConsoleApp" 
    language "C++"
    
    targetdir ("bin/" .. outputdir .. "/%{prj.name}")
    objdir ("bin-int/" .. outputdir .. "/%{prj.name}")
    
    files {
        "tools/**.cpp"
    }
    
    includedirs {
        "%{IncludeDir.NetGuard}",
        "%{IncludeDir.expected}",
        "%{IncludeDir.fmt}",
        "%{IncludeDir.spdlog}",
        "%{IncludeDir.yamlcpp}"
    }
    
    links {
        "NetGuardLib"
    }

-- Unit tests
project "NetGuardTests"
    location "NetGuardTests"
    kind "ConsoleApp"
    language "C++"
    
    targetdir ("bin/" .. outputdir .. "/%{prj.name}")
    objdir ("bin-int/" .. outputdir .. "/%{prj.name}")
    
    files {
        "tests/unit/**.cpp",
        "tests/integration/**.cpp"
    }
    
    includedirs {
        "%{IncludeDir.NetGuard}",
        "%{IncludeDir.expected}",
        "%{IncludeDir.fmt}",
        "%{IncludeDir.spdlog}",
        "%{IncludeDir.catch2}"
    }
    
    links {
        "NetGuardLib"
    }
    
    -- Test-specific settings
    filter "configurations:Debug"
        defines {
            "NG_DEBUG",
            "NG_TESTING"
        }
        runtime "Debug"
        symbols "On"
        
    filter "configurations:Release"
        defines {
            "NG_RELEASE",
            "NG_TESTING"
        }
        runtime "Release"
        symbols "On"  -- Keep symbols for test debugging

-- Benchmarks
project "NetGuardBench"
    location "NetGuardBench"
    kind "ConsoleApp"
    language "C++"
    
    targetdir ("bin/" .. outputdir .. "/%{prj.name}")
    objdir ("bin-int/" .. outputdir .. "/%{prj.name}")
    
    files {
        "tools/benchmark.cpp"
    }
    
    includedirs {
        "%{IncludeDir.NetGuard}",
        "%{IncludeDir.expected}",
        "%{IncludeDir.fmt}",
        "%{IncludeDir.spdlog}"
    }
    
    links {
        "NetGuardLib"
    }
    
    -- Benchmark optimizations
    filter "configurations:*"
        optimize "Speed"
        defines "NG_BENCHMARKING"