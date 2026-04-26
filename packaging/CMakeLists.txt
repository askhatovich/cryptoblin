# Server packaging assets: example config + systemd unit. Installed only when
# building the server (root CMakeLists guards this subdirectory).

include(GNUInstallDirs)

# /etc/cryptoblin/cryptoblin.ini.example — admin copies it to cryptoblin.ini
# and edits in place. We deliberately do not install cryptoblin.ini itself so
# the .deb is not marked as a conffile.
install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/cryptoblin.ini.example
    DESTINATION /etc/cryptoblin
)

# /lib/systemd/system/cryptoblin.service
install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/cryptoblin.service
    DESTINATION /lib/systemd/system
)
