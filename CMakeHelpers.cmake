function(CheckLibrary)
    if (APPLE)
        include_directories(/usr/local/opt/openssl/include)
        link_directories(/usr/local/opt/openssl/lib)

    elseif(UNIX)
        include_directories(/usr/include)
        link_directories(/usr/lib)

    endif (APPLE)
endfunction()

function(LinTargetLibrary Target)
    target_link_libraries(${Target} crypto)
endfunction()
